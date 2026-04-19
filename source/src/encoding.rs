use {
    anyhow::{
        Result,
        bail,
    },
    rmp::encode::{
        write_array_len,
        write_bool,
        write_f64,
        write_map_len,
        write_nil,
        write_sint,
        write_str,
        write_uint,
    },
    serde_json::Value,
};

// msgpack ext type 0, fixext1 = unknown sentinel used by cty
pub const UNKNOWN_BYTES: [u8; 3] = [0xD4, 0x00, 0x00];

/// Encode msgpack null (nil).
pub fn null_msgpack() -> Vec<u8> {
    vec![0xC0]
}

pub(crate) fn msgpack_to_json(val: rmpv::Value) -> Result<Value> {
    match val {
        rmpv::Value::Nil => Ok(Value::Null),
        rmpv::Value::Boolean(b) => Ok(Value::Bool(b)),
        rmpv::Value::Integer(i) => {
            if let Some(n) = i.as_i64() {
                Ok(Value::Number(n.into()))
            } else if let Some(n) = i.as_u64() {
                Ok(Value::Number(n.into()))
            } else {
                bail!("msgpack integer out of JSON range")
            }
        },
        rmpv::Value::F32(f) => Ok({
            let f = f as f64;
            serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)
        }),
        rmpv::Value::F64(f) => Ok(serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null)),
        rmpv::Value::String(s) => Ok(Value::String(s.into_str().unwrap_or_default())),
        rmpv::Value::Binary(b) => Ok(
            Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b)),
        ),
        rmpv::Value::Array(arr) => {
            let items: Result<Vec<_>> = arr.into_iter().map(msgpack_to_json).collect();
            Ok(Value::Array(items?))
        },
        rmpv::Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    rmpv::Value::String(s) => s.into_str().unwrap_or_default(),
                    other => format!("{other:?}"),
                };
                map.insert(key, msgpack_to_json(v)?);
            }
            Ok(Value::Object(map))
        },
        // ext type 0 = cty unknown → null in our representation
        rmpv::Value::Ext(_, _) => Ok(Value::Null),
    }
}

pub(crate) fn json_to_msgpack(value: &Value, buf: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => write_nil(buf)?,
        Value::Bool(b) => write_bool(buf, *b)?,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                write_sint(buf, i)?;
            } else if let Some(u) = n.as_u64() {
                write_uint(buf, u)?;
            } else if let Some(f) = n.as_f64() {
                write_f64(buf, f)?;
            } else {
                write_nil(buf)?;
            }
        },
        Value::String(s) => write_str(buf, s)?,
        Value::Array(arr) => {
            write_array_len(buf, arr.len() as u32)?;
            for v in arr {
                json_to_msgpack(v, buf)?;
            }
        },
        Value::Object(map) => {
            write_map_len(buf, map.len() as u32)?;
            for (k, v) in map {
                write_str(buf, k)?;
                json_to_msgpack(v, buf)?;
            }
        },
    }
    Ok(())
}

/// Build a msgpack map for a resource state, given the schema attributes and
/// user-provided JSON values.  Computed-only attributes not supplied by the user
/// are emitted as the cty unknown sentinel so the provider can fill them in.
pub(crate) fn build_config_msgpack(
    attrs: &[SchemaAttr],
    user_values: &serde_json::Map<String, Value>,
    use_unknown_for_computed: bool,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    write_map_len(&mut buf, attrs.len() as u32)?;
    for attr in attrs {
        write_str(&mut buf, &attr.name)?;
        let computed_only = attr.computed && !attr.optional && !attr.required;
        if let Some(v) = user_values.get(&attr.name) {
            json_to_msgpack(v, &mut buf)?;
        } else if computed_only && use_unknown_for_computed {
            buf.extend_from_slice(&UNKNOWN_BYTES);
        } else {
            rmp::encode::write_nil(&mut buf)?;
        }
    }
    Ok(buf)
}

#[derive(Debug, Clone)]
pub struct SchemaAttr {
    pub name: String,
    pub required: bool,
    pub optional: bool,
    pub computed: bool,
}
