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
    return vec![0xC0];
}

pub(crate) fn msgpack_to_json(val: rmpv::Value) -> Result<Value> {
    match val {
        rmpv::Value::Nil => return Ok(Value::Null),
        rmpv::Value::Boolean(b) => return Ok(Value::Bool(b)),
        rmpv::Value::Integer(i) => {
            if let Some(n) = i.as_i64() {
                return Ok(Value::Number(n.into()));
            } else if let Some(n) = i.as_u64() {
                return Ok(Value::Number(n.into()));
            } else {
                bail!("msgpack integer out of JSON range")
            }
        },
        rmpv::Value::F32(f) => {
            let f = f as f64;
            return Ok(serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null));
        },
        rmpv::Value::F64(f) => {
            return Ok(serde_json::Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null));
        },
        rmpv::Value::String(s) => {
            return Ok(
                Value::String(s.into_str().ok_or_else(|| anyhow::anyhow!("msgpack string is not valid UTF-8"))?),
            );
        },
        rmpv::Value::Binary(b) => {
            return Ok(Value::String(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &b)));
        },
        rmpv::Value::Array(arr) => {
            let items: Result<Vec<_>> = arr.into_iter().map(msgpack_to_json).collect();
            return Ok(Value::Array(items?));
        },
        rmpv::Value::Map(pairs) => {
            let mut map = serde_json::Map::new();
            for (k, v) in pairs {
                let key = match k {
                    rmpv::Value::String(s) => s
                        .into_str()
                        .ok_or_else(|| anyhow::anyhow!("msgpack map key is not valid UTF-8"))?,
                    other => bail!("msgpack map key is not a string: {:?}", other),
                };
                map.insert(key, msgpack_to_json(v)?);
            }
            return Ok(Value::Object(map));
        },
        // ext type 0 = cty unknown → null in our representation
        rmpv::Value::Ext(_, _) => return Ok(Value::Null),
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
    return Ok(());
}

/// How a nested block or nested attribute object is wrapped in its parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaNesting {
    /// A single object, null when absent.
    Single,
    /// A single object, never null; absent means an object with all-null attributes.
    /// Only valid for nested blocks.
    Group,
    /// A list of objects, empty when absent.
    List,
    /// A set of objects, empty when absent.
    Set,
    /// A string-keyed map of objects, empty when absent.
    Map,
}

/// A cty type, as the JSON type encoding sent by the provider (e.g. `"string"` or
/// `["list","string"]`).
#[derive(Debug, Clone)]
pub struct SchemaAttrTypeCty {
    pub type_json: Vec<u8>,
}

/// A protocol 6 nested attribute: an object (or collection of objects) whose
/// fields have their own required/optional/computed flags.
#[derive(Debug, Clone)]
pub struct SchemaAttrTypeNested {
    pub nesting: SchemaNesting,
    pub attrs: Vec<SchemaAttr>,
}

#[derive(Debug, Clone)]
pub enum SchemaAttrType {
    Cty(SchemaAttrTypeCty),
    Nested(SchemaAttrTypeNested),
}

#[derive(Debug, Clone)]
pub struct SchemaAttr {
    pub name: String,
    pub required: bool,
    pub optional: bool,
    pub computed: bool,
    pub sensitive: bool,
    pub write_only: bool,
    pub deprecated: bool,
    pub deprecation_message: String,
    pub description: String,
    pub type_: SchemaAttrType,
}

impl SchemaAttr {
    /// Computed with no required/optional flag: the provider alone decides the value.
    pub fn pure_computed(&self) -> bool {
        return self.computed && !self.optional && !self.required;
    }
}

/// A nested block (SDKv2 style `block_types`).  In values the block appears as an
/// attribute named `name` whose shape is determined by `nesting`.
#[derive(Debug, Clone)]
pub struct SchemaNestedBlock {
    pub name: String,
    pub nesting: SchemaNesting,
    pub min_items: i64,
    pub max_items: i64,
    pub block: SchemaBlock,
}

#[derive(Debug, Clone, Default)]
pub struct SchemaBlock {
    pub attrs: Vec<SchemaAttr>,
    pub blocks: Vec<SchemaNestedBlock>,
    pub deprecated: bool,
    pub deprecation_message: String,
    pub description: String,
}

/// Encode a cty object value for a block (or nested attribute object) as msgpack.
///
/// Attributes absent from `values` are nil, except that pure-computed attributes
/// are emitted as the cty unknown sentinel when `use_unknown_for_computed` is set,
/// so the provider knows to fill them in.  Absent nested blocks are encoded the
/// way Terraform encodes an absent block: nil for `Single`, an all-null object for
/// `Group`, and an empty collection for `List`/`Set`/`Map`.
pub(crate) fn encode_block(
    attrs: &[SchemaAttr],
    blocks: &[SchemaNestedBlock],
    values: &serde_json::Map<String, Value>,
    use_unknown_for_computed: bool,
    buf: &mut Vec<u8>,
) -> Result<()> {
    write_map_len(buf, (attrs.len() + blocks.len()) as u32)?;
    for attr in attrs {
        write_str(buf, &attr.name)?;
        match values.get(&attr.name) {
            Some(v) if !v.is_null() => {
                match &attr.type_ {
                    SchemaAttrType::Cty(_) => {
                        json_to_msgpack(v, buf)?;
                    },
                    SchemaAttrType::Nested(nested) => {
                        encode_nested(
                            &nested.attrs,
                            &[],
                            nested.nesting,
                            &attr.name,
                            Some(v),
                            use_unknown_for_computed,
                            buf,
                        )?;
                    },
                }
            },
            _ => {
                if attr.pure_computed() && use_unknown_for_computed {
                    buf.extend_from_slice(&UNKNOWN_BYTES);
                } else {
                    write_nil(buf)?;
                }
            },
        }
    }
    for block in blocks {
        write_str(buf, &block.name)?;
        encode_nested(
            &block.block.attrs,
            &block.block.blocks,
            block.nesting,
            &block.name,
            values.get(&block.name),
            use_unknown_for_computed,
            buf,
        )?;
    }
    return Ok(());
}

/// Encode the value of a nested block or nested attribute according to its nesting
/// mode.  `value` is `None` (or null) when the user did not supply it.
fn encode_nested(
    attrs: &[SchemaAttr],
    blocks: &[SchemaNestedBlock],
    nesting: SchemaNesting,
    name: &str,
    value: Option<&Value>,
    use_unknown_for_computed: bool,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let value = match value {
        Some(Value::Null) | None => None,
        Some(v) => Some(v),
    };
    match nesting {
        SchemaNesting::Single => {
            match value {
                Some(Value::Object(obj)) => {
                    encode_block(attrs, blocks, obj, use_unknown_for_computed, buf)?;
                },
                Some(other) => bail!("Nested [{}] must be an object, got {}", name, other),
                None => write_nil(buf)?,
            }
        },
        SchemaNesting::Group => {
            match value {
                Some(Value::Object(obj)) => {
                    encode_block(attrs, blocks, obj, use_unknown_for_computed, buf)?;
                },
                Some(other) => bail!("Nested [{}] must be an object, got {}", name, other),
                None => {
                    encode_block(attrs, blocks, &serde_json::Map::new(), use_unknown_for_computed, buf)?;
                },
            }
        },
        SchemaNesting::List | SchemaNesting::Set => {
            match value {
                Some(Value::Array(items)) => {
                    write_array_len(buf, items.len() as u32)?;
                    for item in items {
                        match item {
                            Value::Object(obj) => {
                                encode_block(attrs, blocks, obj, use_unknown_for_computed, buf)?;
                            },
                            other => bail!("Elements of nested [{}] must be objects, got {}", name, other),
                        }
                    }
                },
                Some(other) => bail!("Nested [{}] must be an array, got {}", name, other),
                None => {
                    write_array_len(buf, 0)?;
                },
            }
        },
        SchemaNesting::Map => {
            match value {
                Some(Value::Object(entries)) => {
                    write_map_len(buf, entries.len() as u32)?;
                    for (k, item) in entries {
                        write_str(buf, k)?;
                        match item {
                            Value::Object(obj) => {
                                encode_block(attrs, blocks, obj, use_unknown_for_computed, buf)?;
                            },
                            other => bail!("Values of nested map [{}] must be objects, got {}", name, other),
                        }
                    }
                },
                Some(other) => bail!("Nested [{}] must be an object (map), got {}", name, other),
                None => {
                    write_map_len(buf, 0)?;
                },
            }
        },
    }
    return Ok(());
}

/// Compute Terraform's "proposed new state" for a block: for each attribute take
/// the config value, except that a null config value for a computed attribute
/// takes the prior value.  Pure-computed attributes are left null so that
/// `encode_block` can turn them into the unknown sentinel.  Nested blocks and
/// nested attributes recurse, pairing prior and config elements by index (lists of
/// equal length) or key (maps); sets and lists of differing length take the config
/// as-is.
pub(crate) fn proposed_new_block(
    attrs: &[SchemaAttr],
    blocks: &[SchemaNestedBlock],
    prior: Option<&serde_json::Map<String, Value>>,
    config: &serde_json::Map<String, Value>,
) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for attr in attrs {
        let config_v = config.get(&attr.name).filter(|v| !v.is_null());
        let prior_v = prior.and_then(|p| p.get(&attr.name)).filter(|v| !v.is_null());
        let v = match config_v {
            None => {
                if attr.computed && !attr.pure_computed() {
                    prior_v.cloned()
                } else {
                    None
                }
            },
            Some(cv) => {
                match &attr.type_ {
                    SchemaAttrType::Cty(_) => Some(cv.clone()),
                    SchemaAttrType::Nested(nested) => {
                        Some(proposed_new_nested(&nested.attrs, &[], nested.nesting, prior_v, cv))
                    },
                }
            },
        };
        if let Some(v) = v {
            out.insert(attr.name.clone(), v);
        }
    }
    for block in blocks {
        let config_v = config.get(&block.name).filter(|v| !v.is_null());
        let prior_v = prior.and_then(|p| p.get(&block.name)).filter(|v| !v.is_null());
        if let Some(cv) = config_v {
            out.insert(
                block.name.clone(),
                proposed_new_nested(&block.block.attrs, &block.block.blocks, block.nesting, prior_v, cv),
            );
        }
    }
    return out;
}

fn proposed_new_nested(
    attrs: &[SchemaAttr],
    blocks: &[SchemaNestedBlock],
    nesting: SchemaNesting,
    prior: Option<&Value>,
    config: &Value,
) -> Value {
    match nesting {
        SchemaNesting::Single | SchemaNesting::Group => {
            match (prior, config) {
                (Some(Value::Object(p)), Value::Object(c)) => {
                    return Value::Object(proposed_new_block(attrs, blocks, Some(p), c));
                },
                (_, Value::Object(c)) => {
                    return Value::Object(proposed_new_block(attrs, blocks, None, c));
                },
                _ => return config.clone(),
            }
        },
        SchemaNesting::List => {
            match (prior, config) {
                (Some(Value::Array(p)), Value::Array(c)) if p.len() == c.len() => {
                    let mut out = Vec::new();
                    for (pe, ce) in p.iter().zip(c.iter()) {
                        match (pe, ce) {
                            (Value::Object(po), Value::Object(co)) => {
                                out.push(Value::Object(proposed_new_block(attrs, blocks, Some(po), co)));
                            },
                            _ => out.push(ce.clone()),
                        }
                    }
                    return Value::Array(out);
                },
                _ => return config.clone(),
            }
        },
        SchemaNesting::Set => {
            return config.clone();
        },
        SchemaNesting::Map => {
            match (prior, config) {
                (Some(Value::Object(p)), Value::Object(c)) => {
                    let mut out = serde_json::Map::new();
                    for (k, ce) in c {
                        match (p.get(k), ce) {
                            (Some(Value::Object(po)), Value::Object(co)) => {
                                out.insert(
                                    k.clone(),
                                    Value::Object(proposed_new_block(attrs, blocks, Some(po), co)),
                                );
                            },
                            _ => {
                                out.insert(k.clone(), ce.clone());
                            },
                        }
                    }
                    return Value::Object(out);
                },
                _ => return config.clone(),
            }
        },
    }
}
