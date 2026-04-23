use {
    crate::{
        encoding::{
            SchemaAttr,
            build_config_msgpack,
            json_to_msgpack,
            msgpack_to_json,
            null_msgpack,
        },
        provider::{
            ProviderInner,
            v_::{
                ProviderInnerImpl,
                ProviderShared,
            },
        },
    },
    anyhow::Context,
    schemask::{
        Maskoid,
        MaskoidField,
    },
    schemask::v1::Schemask,
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        collections::HashMap,
        path::Path,
        sync::Arc,
    },
};

mod encoding;
mod provider;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Params(pub serde_json::Map<String, serde_json::Value>);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResourceState {
    pub state: serde_json::Value,
    pub schema_version: i64,
}

#[derive(Clone)]
pub struct ExTerra {
    provider_shared: provider::v_::ProviderShared,
}

pub struct Provider {
    p: ProviderInner,
}

impl ExTerra {
    pub fn new() -> Result<Self, anyhow::Error> {
        let key_pair =
            rcgen
            ::KeyPair
            ::generate().context("Error generating self signed tls cert for local plugin communication")?;
        let cert =
            rcgen::CertificateParams::default()
                .self_signed(&key_pair)
                .context("Error parsing self signed tls cert for local plugin communication")?;
        return Ok(ExTerra { provider_shared: ProviderShared {
            crypto: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            own_pub_pem: cert.pem(),
            own_pub_der: cert.der().to_vec(),
            own_priv_der: key_pair.serialize_der(),
        } });
    }

    pub async fn provider(&self, binary: &Path, config: Params) -> Result<Provider, anyhow::Error> {
        let config_json = serde_json::Value::Object(config.0.clone());
        let provider = Provider { p: provider::new(&self.provider_shared, binary, config.0).await? };
        let schema = provider.provider_schemask()?;
        check_schema(&schema, &config_json)?;
        return Ok(provider);
    }
}

fn check_schema(schema: &Schemask, data: &serde_json::Value) -> Result<(), anyhow::Error> {
    schemask::validate(&schemask::Schemask::V1(schema.clone()), None, data)
        .map_err(|e| anyhow::anyhow!("schema validation failed: {}", e))
}

impl Provider {
    pub fn list_resource_types(&self) -> Vec<String> {
        return self.p.list_resource_types();
    }

    pub fn provider_schemask(&self) -> Result<Schemask, anyhow::Error> {
        let attrs = self.p.get_provider_schema_attrs();
        let mut bindings = HashMap::new();
        bindings.insert("Params".to_string(), attrs_to_schemask_record(&attrs, false)?);
        return Ok(Schemask {
            bindings: bindings,
            default: Some("Params".to_string()),
        });
    }

    pub fn params_schemask(&self, resource_type: &str) -> Result<Schemask, anyhow::Error> {
        let attrs = self.p.get_resource_schema(resource_type)?;
        let mut bindings = HashMap::new();
        bindings.insert("Params".to_string(), attrs_to_schemask_record(&attrs, false)?);
        return Ok(Schemask {
            bindings: bindings,
            default: Some("Params".to_string()),
        });
    }

    pub fn state_schemask(&self, resource_type: &str) -> Result<Schemask, anyhow::Error> {
        let attrs = self.p.get_resource_schema(resource_type)?;
        let mut bindings = HashMap::new();
        bindings.insert("State".to_string(), attrs_to_schemask_record(&attrs, true)?);
        return Ok(Schemask {
            bindings: bindings,
            default: Some("State".to_string()),
        });
    }

    async fn maybe_upgrade_state(&mut self, resource_type: &str, state: ResourceState) -> Result<ResourceState, anyhow::Error> {
        let current_version = self.p.get_resource_schema_version(resource_type);
        if state.schema_version < current_version {
            let raw_json = serde_json::to_vec(&state.state)
                .context("Error serializing state for upgrade")?;
            let upgraded_mp = self.p.upgrade_resource_state(resource_type, state.schema_version, raw_json).await?;
            return Ok(state_from_msgpack(&upgraded_mp, current_version)?);
        }
        Ok(state)
    }

    pub async fn refresh(&mut self, resource_type: &str, state: ResourceState) -> Result<ResourceState, anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        let current_mp = state_to_msgpack(&state)?;
        let new_mp = self.p.read(resource_type, current_mp, vec![]).await?;
        let current_version = self.p.get_resource_schema_version(resource_type);
        return Ok(state_from_msgpack(&new_mp, current_version)?);
    }

    pub async fn import(&mut self, resource_type: &str, id: &str) -> Result<ResourceState, anyhow::Error> {
        let new_mp = self.p.import(resource_type, id).await?;
        let current_version = self.p.get_resource_schema_version(resource_type);
        return Ok(state_from_msgpack(&new_mp, current_version)?);
    }

    pub async fn create(&mut self, type_: &str, input: Params) -> Result<ResourceState, anyhow::Error> {
        if let Some(datasource_type) = type_.strip_prefix("data.") {
            let attrs = self.p.get_datasource_schema(datasource_type)?;
            let schema = {
                let mut bindings = HashMap::new();
                bindings.insert("Params".to_string(), attrs_to_schemask_record(&attrs, false)?);
                Schemask {
                    bindings,
                    default: Some("Params".to_string()),
                }
            };
            check_schema(&schema, &serde_json::Value::Object(input.0.clone()))?;
            let config_mp = build_config_msgpack(&attrs, &input.0, false)?;
            let state_mp = self.p.read_datasource(datasource_type, config_mp).await?;
            let current_version = self.p.get_resource_schema_version(datasource_type);
            return Ok(state_from_msgpack(&state_mp, current_version)?);
        }
        check_schema(&self.params_schemask(type_)?, &serde_json::Value::Object(input.0.clone()))?;
        let attrs = self.p.get_resource_schema(type_)?;
        let config_mp = build_config_msgpack(&attrs, &input.0, false)?;
        let proposed_mp = build_config_msgpack(&attrs, &input.0, true)?;
        let prior_mp = null_msgpack();
        let plan = self.p.plan(type_, prior_mp.clone(), proposed_mp, config_mp.clone(), vec![]).await?;
        let new_state_mp =
            self.p.apply(type_, prior_mp, plan.planned_state, config_mp, plan.planned_private).await?;
        let current_version = self.p.get_resource_schema_version(type_);
        return Ok(state_from_msgpack(&new_state_mp, current_version)?);
    }

    pub async fn modify(
        &mut self,
        resource_type: &str,
        state: ResourceState,
        params: Params,
    ) -> Result<ResourceState, anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        check_schema(&self.params_schemask(resource_type)?, &serde_json::Value::Object(params.0.clone()))?;
        let attrs = self.p.get_resource_schema(resource_type)?;
        let prior_mp = state_to_msgpack(&state)?;

        // Computed-only attributes (no required/optional flag) are filled in by the
        // provider.  They must appear as the unknown sentinel in proposed_new_state so
        // the provider knows to recompute them.  Copying the prior value would tell the
        // provider "this attr won't change" and suppress the update.
        let pure_computed_field_names: std::collections::HashSet<&str> =
            attrs.iter().filter(|a| a.computed && !a.optional && !a.required).map(|a| a.name.as_str()).collect();

        // Build a merged map: prior optional/required values + new_values override.
        // Computed-only attrs are intentionally omitted so they become unknown.
        let mut merged = serde_json::Map::new();
        if let serde_json::Value::Object(prior_map) = state.state {
            for (k, v) in prior_map {
                if !pure_computed_field_names.contains(k.as_str()) {
                    merged.insert(k.clone(), v.clone());
                }
            }
        }
        for (k, v) in &params.0 {
            merged.insert(k.clone(), v.clone());
        }
        let config_mp = build_config_msgpack(&attrs, &params.0, false)?;
        let proposed_mp = build_config_msgpack(&attrs, &merged, true)?;
        let plan = self.p.plan(&resource_type, prior_mp.clone(), proposed_mp, config_mp.clone(), vec![]).await?;
        if plan.requires_replace {
            return Err(
                anyhow::anyhow!(
                    "One or more changed parameters require resource [{}] to be deleted and recreated, cannot modify",
                    resource_type
                ),
            );
        }
        let new_state_mp =
            self.p.apply(resource_type, prior_mp, plan.planned_state, config_mp, plan.planned_private).await?;
        let current_version = self.p.get_resource_schema_version(resource_type);
        return Ok(state_from_msgpack(&new_state_mp, current_version)?);
    }

    pub async fn delete(&mut self, resource_type: &str, state: ResourceState) -> Result<(), anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        let prior_mp = state_to_msgpack(&state)?;
        let null_mp = null_msgpack();
        let plan = self.p.plan(&resource_type, prior_mp.clone(), null_mp.clone(), null_mp.clone(), vec![]).await?;
        self.p.apply(&resource_type, prior_mp, plan.planned_state, null_mp, plan.planned_private).await?;
        return Ok(());
    }
}

fn cty_type_to_maskoid(type_json: &serde_json::Value) -> Result<Maskoid, anyhow::Error> {
    match type_json {
        serde_json::Value::String(s) => match s.as_str() {
            "string" => return Ok(Maskoid::String),
            "number" => return Ok(Maskoid::Float),
            "bool" => return Ok(Maskoid::Bool),
            "dynamic" => return Ok(Maskoid::Any),
            other => return Err(anyhow::anyhow!("Unknown cty primitive type: {}", other)),
        },
        serde_json::Value::Array(arr) if arr.len() >= 2 => {
            let kind = match &arr[0] {
                serde_json::Value::String(s) => s.clone(),
                _ => return Err(anyhow::anyhow!("cty collection type kind must be a string")),
            };
            match kind.as_str() {
                "list" => return Ok(Maskoid::list(cty_type_to_maskoid(&arr[1])?)),
                "set" => return Ok(Maskoid::set(cty_type_to_maskoid(&arr[1])?)),
                "map" => return Ok(Maskoid::string_map(cty_type_to_maskoid(&arr[1])?)),
                "tuple" => {
                    let elems = match &arr[1] {
                        serde_json::Value::Array(a) => a,
                        _ => return Err(anyhow::anyhow!("cty tuple elements must be an array")),
                    };
                    let mut elements = Vec::new();
                    for elem in elems {
                        elements.push(MaskoidField::new(cty_type_to_maskoid(elem)?));
                    }
                    return Ok(Maskoid::tuple(elements));
                },
                "object" => {
                    let obj = match &arr[1] {
                        serde_json::Value::Object(o) => o,
                        _ => return Err(anyhow::anyhow!("cty object fields must be an object")),
                    };
                    let mut fields = HashMap::new();
                    for (key, type_val) in obj {
                        fields.insert(key.clone(), MaskoidField::new(cty_type_to_maskoid(type_val)?));
                    }
                    return Ok(Maskoid::record(fields));
                },
                other => return Err(anyhow::anyhow!("Unknown cty collection type: {}", other)),
            }
        },
        _ => return Err(anyhow::anyhow!("Invalid cty type JSON")),
    }
}

fn attrs_to_schemask_record(attrs: &[SchemaAttr], include_computed_only: bool) -> Result<Maskoid, anyhow::Error> {
    let mut fields = HashMap::new();
    for attr in attrs {
        let pure_computed = attr.computed && !attr.optional && !attr.required;
        if !include_computed_only && pure_computed {
            continue;
        }
        let inner = cty_type_to_maskoid(
            &serde_json::from_slice(&attr.type_)
                .with_context(|| format!("Error parsing cty type for attribute [{}]", attr.name))?,
        ).with_context(|| format!("Error converting cty type for attribute [{}]", attr.name))?;
        let maskoid = if attr.required && !attr.optional {
            inner
        } else {
            Maskoid::option(inner)
        };
        fields.insert(attr.name.clone(), MaskoidField::new(maskoid));
    }
    return Ok(Maskoid::record(fields));
}

fn state_to_msgpack(state: &ResourceState) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    json_to_msgpack(&state.state, &mut buf)?;
    Ok(buf)
}

fn state_from_msgpack(new_state_mp: &[u8], schema_version: i64) -> Result<ResourceState, anyhow::Error> {
    if new_state_mp.is_empty() {
        return Ok(ResourceState { state: serde_json::Value::Null, schema_version });
    }
    let mut rd = &new_state_mp[..];
    return Ok(
        ResourceState {
            state: msgpack_to_json(
                rmpv::decode::read_value(&mut rd).context("Error decoding resource state")?,
            ).context("Error converting resource state messagepack to json")?,
            schema_version,
        },
    );
}

#[cfg(test)]
mod tests {
    use {
        crate::{
            ExTerra,
            Params,
            Provider,
            ResourceState,
        },
        std::{
            path::{
                Path,
                PathBuf,
            },
        },
        tempfile::TempDir,
    };

    const RESOURCE_TYPE: &str = "local_file";

    async fn provider() -> Result<Provider, anyhow::Error> {
        let et = ExTerra::new()?;
        return Ok(
            et
                .provider(
                    &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("terraform-provider-local_v2.8.0_x5"),
                    Default::default(),
                )
                .await?,
        );
    }

    async fn run_create(
        p: &mut Provider,
        target_file: &Path,
        content: &str,
    ) -> anyhow::Result<ResourceState, anyhow::Error> {
        let state =
            p
                .create(
                    RESOURCE_TYPE,
                    Params(
                        [
                            (
                                "filename".to_string(),
                                serde_json::Value::String(target_file.to_str().unwrap().to_string()),
                            ),
                            ("content".to_string(), serde_json::Value::String(content.to_string())),
                        ]
                            .into_iter()
                            .collect(),
                    ),
                )
                .await?;
        return Ok(state);
    }

    const DATASOURCE_TYPE: &str = "data.local_file";

    #[tokio::test]
    async fn test_create_datasource_reads_file() -> anyhow::Result<()> {
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("input.txt");
        std::fs::write(&target, "datasource content")?;

        let mut p = provider().await?;
        let state = p
            .create(
                DATASOURCE_TYPE,
                Params(
                    [(
                        "filename".to_string(),
                        serde_json::Value::String(target.to_str().unwrap().to_string()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            )
            .await?;

        assert_eq!(state.state["content"], "datasource content");
        return Ok(());
    }

    #[tokio::test]
    async fn test_create_writes_file() -> anyhow::Result<()> {
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");
        let mut p = provider().await?;
        run_create(&mut p, &target, "hello exterra").await?;
        assert!(target.exists(), "managed file was not created");
        assert_eq!(std::fs::read_to_string(&target)?, "hello exterra");
        return Ok(());
    }

    #[tokio::test]
    async fn test_modify_requires_replace_errors() -> anyhow::Result<()> {
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");
        let mut p = provider().await?;
        let state = run_create(&mut p, &target, "original content").await?;
        p
            .modify(
                "local_file",
                state,
                Params(
                    [
                        (format!("filename"), serde_json::Value::String(target.to_str().unwrap().to_string())),
                        (format!("content"), serde_json::Value::String(format!("updated content"))),
                    ]
                        .into_iter()
                        .collect(),
                ),
            )
            .await
            .expect_err("modify with ForceNew change should fail");
        return Ok(());
    }

    #[tokio::test]
    async fn test_delete_removes_file() -> anyhow::Result<()> {
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");
        let mut p = provider().await?;
        let state = run_create(&mut p, &target, "to be deleted").await?;
        assert!(target.exists(), "file should exist before delete");
        p.delete(RESOURCE_TYPE, state).await?;
        assert!(!target.exists(), "managed file should have been deleted");
        return Ok(());
    }
}
