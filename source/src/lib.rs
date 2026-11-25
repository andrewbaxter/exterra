use {
    crate::{
        encoding::{
            SchemaAttr,
            SchemaAttrType,
            SchemaNestedBlock,
            SchemaNesting,
            encode_block,
            json_to_msgpack,
            msgpack_to_json,
            null_msgpack,
            proposed_new_block,
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
        latest::SchemaskV1,
    },
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        collections::BTreeMap,
        path::Path,
        sync::Arc,
    },
};

mod encoding;
mod provider;

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Params(pub serde_json::Map<String, serde_json::Value>);

/// Serde adapter so provider private bytes appear as base64 in JSON state files.
mod base64_bytes {
    use serde::{
        Deserialize,
        Deserializer,
        Serializer,
    };

    pub fn serialize<S: Serializer>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        return serializer.serialize_str(&base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes));
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        return base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &s,
        ).map_err(serde::de::Error::custom);
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResourceState {
    pub state: serde_json::Value,
    pub schema_version: i64,
    /// Opaque provider-private data (e.g. framework timeouts).  Must be round-tripped
    /// unchanged; providers that rely on it misbehave if it is dropped.
    #[serde(default, with = "base64_bytes")]
    pub private: Vec<u8>,
}

pub const DATA_SOURCE_PREFIX: &str = "data.";

#[derive(Debug, Clone)]
pub struct RequiresReplace {
    pub resource_type: String,
    pub paths: Vec<Vec<String>>,
}

impl std::fmt::Display for RequiresReplace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let paths: Vec<String> = self.paths.iter().map(|p| p.join(".")).collect();
        return write!(
            f,
            "One or more changed parameters ({}) require resource [{}] to be deleted and recreated, cannot modify",
            paths.join(", "),
            self.resource_type
        );
    }
}

impl std::error::Error for RequiresReplace { }

#[derive(Debug, Clone)]
pub struct ModifyPlan {
    pub requires_replace: Vec<Vec<String>>,
}

#[derive(Clone)]
pub struct ExTerra {
    provider_shared: ProviderShared,
}

pub struct Provider {
    p: ProviderInner,
}

impl ExTerra {
    /// `terraform_version` is the host version reported to providers when configuring
    /// them (Terraform and OpenTofu each send their own version); defaults to `1.0.0`.
    pub fn new(terraform_version: Option<String>) -> Result<Self, anyhow::Error> {
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
            terraform_version: terraform_version.unwrap_or_else(|| "1.0.0".to_string()),
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

fn check_schema(schema: &SchemaskV1, data: &serde_json::Value) -> Result<(), anyhow::Error> {
    return schemask::validate(
        &schemask::Schemask::V1(schema.clone()),
        None,
        data,
    ).map_err(|e| anyhow::anyhow!("schema validation failed: {}", e));
}

fn single_schemask(name: &str, maskoid: Maskoid) -> SchemaskV1 {
    let mut bindings = BTreeMap::new();
    bindings.insert(name.to_string(), maskoid);
    return SchemaskV1 {
        bindings: bindings,
        default: Some(name.to_string()),
    };
}

impl Provider {
    pub fn list_resource_types(&self) -> Vec<String> {
        return self.p.list_resource_types();
    }

    pub fn list_datasource_types(&self) -> Vec<String> {
        return self.p.list_datasource_types();
    }

    fn block_for(&self, type_: &str) -> Result<crate::encoding::SchemaBlock, anyhow::Error> {
        if let Some(ds) = type_.strip_prefix(DATA_SOURCE_PREFIX) {
            return self.p.get_datasource_schema(ds);
        }
        return self.p.get_resource_schema(type_);
    }

    /// OS pid of the provider process.  It is killed when this `Provider` is dropped.
    pub fn process_id(&self) -> u32 {
        return self.p.process_id();
    }

    pub fn provider_schemask(&self) -> Result<SchemaskV1, anyhow::Error> {
        let block = self.p.get_provider_schema();
        return Ok(
            single_schemask(
                "Params",
                block_to_schemask_record(&block.attrs, &block.blocks, &block.description, false)?,
            ),
        );
    }

    pub fn params_schemask(&self, resource_type: &str) -> Result<SchemaskV1, anyhow::Error> {
        let block = self.block_for(resource_type)?;
        return Ok(
            single_schemask(
                "Params",
                block_to_schemask_record(&block.attrs, &block.blocks, &block.description, false)?,
            ),
        );
    }

    pub fn state_schemask(&self, resource_type: &str) -> Result<SchemaskV1, anyhow::Error> {
        let block = self.block_for(resource_type)?;
        return Ok(
            single_schemask(
                "State",
                block_to_schemask_record(&block.attrs, &block.blocks, &block.description, true)?,
            ),
        );
    }

    async fn maybe_upgrade_state(
        &self,
        resource_type: &str,
        state: ResourceState,
    ) -> Result<ResourceState, anyhow::Error> {
        let current_version = self.p.get_resource_schema_version(resource_type)?;
        if state.schema_version < current_version {
            let raw_json = serde_json::to_vec(&state.state).context("Error serializing state for upgrade")?;
            let upgraded_mp = self.p.upgrade_resource_state(resource_type, state.schema_version, raw_json).await?;
            return Ok(state_from_msgpack(&upgraded_mp, state.private, current_version)?);
        }
        return Ok(state);
    }

    pub async fn refresh(&self, resource_type: &str, state: ResourceState) -> Result<ResourceState, anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        let current_mp = state_to_msgpack(&state)?;
        let new = self.p.read(resource_type, current_mp, state.private).await?;
        let current_version = self.p.get_resource_schema_version(resource_type)?;
        return Ok(state_from_msgpack(&new.state, new.private, current_version)?);
    }

    pub async fn import(&self, resource_type: &str, id: &str) -> Result<ResourceState, anyhow::Error> {
        // Import typically only seeds the id; Terraform always follows it with a read to
        // populate the rest of the state.
        let imported = self.p.import(resource_type, id).await?;
        let new = self.p.read(resource_type, imported.state, imported.private).await?;
        let current_version = self.p.get_resource_schema_version(resource_type)?;
        let state = state_from_msgpack(&new.state, new.private, current_version)?;
        if state.state.is_null() {
            return Err(anyhow::anyhow!("Resource [{}] with id [{}] not found", resource_type, id));
        }
        return Ok(state);
    }

    pub async fn create(&self, type_: &str, input: Params) -> Result<ResourceState, anyhow::Error> {
        if let Some(datasource_type) = type_.strip_prefix(DATA_SOURCE_PREFIX) {
            let block = self.p.get_datasource_schema(datasource_type)?;
            check_schema(
                &single_schemask(
                    "Params",
                    block_to_schemask_record(&block.attrs, &block.blocks, &block.description, false)?,
                ),
                &serde_json::Value::Object(input.0.clone()),
            )?;
            let mut config_mp = Vec::new();
            encode_block(&block.attrs, &block.blocks, &input.0, false, &mut config_mp)?;
            let state_mp = self.p.read_datasource(datasource_type, config_mp).await?;

            // Datasources are not versioned or upgraded.
            return Ok(state_from_msgpack(&state_mp, vec![], 0)?);
        }
        check_schema(&self.params_schemask(type_)?, &serde_json::Value::Object(input.0.clone()))?;
        let block = self.p.get_resource_schema(type_)?;
        let mut config_mp = Vec::new();
        encode_block(&block.attrs, &block.blocks, &input.0, false, &mut config_mp)?;
        let proposed = proposed_new_block(&block.attrs, &block.blocks, None, &input.0);
        let mut proposed_mp = Vec::new();
        encode_block(&block.attrs, &block.blocks, &proposed, true, &mut proposed_mp)?;
        let prior_mp = null_msgpack();
        let plan = self.p.plan(type_, prior_mp.clone(), proposed_mp, config_mp.clone(), vec![]).await?;
        let new = self.p.apply(type_, prior_mp, plan.planned_state, config_mp, plan.planned_private).await?;
        let current_version = self.p.get_resource_schema_version(type_)?;
        return Ok(state_from_msgpack(&new.state, new.private, current_version)?);
    }

    pub async fn plan_modify(
        &self,
        resource_type: &str,
        state: ResourceState,
        params: Params,
    ) -> Result<ModifyPlan, anyhow::Error> {
        let (plan, _, _, _) = self.plan_modify_inner(resource_type, state, params).await?;
        return Ok(ModifyPlan { requires_replace: plan.requires_replace });
    }

    async fn plan_modify_inner(
        &self,
        resource_type: &str,
        state: ResourceState,
        params: Params,
    ) -> Result<(crate::provider::v_::PlanResult, Vec<u8>, Vec<u8>, ResourceState), anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        check_schema(&self.params_schemask(resource_type)?, &serde_json::Value::Object(params.0.clone()))?;
        let block = self.p.get_resource_schema(resource_type)?;
        let prior_mp = state_to_msgpack(&state)?;

        // `params` is the complete config.  Follow Terraform's proposed-new-state rule:
        // each attribute takes the config value, except that a null config value for a
        // computed attribute takes the prior value.  Non-computed attributes omitted from
        // params are therefore null in both config and proposed_new_state.
        //
        // Pure-computed attributes are an intentional exception: they are sent as the
        // unknown sentinel so the provider knows to recompute them.  Copying the prior
        // value would tell the provider "this attr won't change" and suppress the update.
        let prior_map = match &state.state {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        };
        let proposed = proposed_new_block(&block.attrs, &block.blocks, prior_map, &params.0);
        let mut config_mp = Vec::new();
        encode_block(&block.attrs, &block.blocks, &params.0, false, &mut config_mp)?;
        let mut proposed_mp = Vec::new();
        encode_block(&block.attrs, &block.blocks, &proposed, true, &mut proposed_mp)?;
        let plan =
            self
                .p
                .plan(&resource_type, prior_mp.clone(), proposed_mp, config_mp.clone(), state.private.clone())
                .await?;
        return Ok((plan, prior_mp, config_mp, state));
    }

    pub async fn modify(
        &self,
        resource_type: &str,
        state: ResourceState,
        params: Params,
    ) -> Result<ResourceState, anyhow::Error> {
        let (plan, prior_mp, config_mp, _state) = self.plan_modify_inner(resource_type, state, params).await?;
        if !plan.requires_replace.is_empty() {
            return Err(anyhow::Error::new(RequiresReplace {
                resource_type: resource_type.to_string(),
                paths: plan.requires_replace,
            }));
        }
        let new = self.p.apply(resource_type, prior_mp, plan.planned_state, config_mp, plan.planned_private).await?;
        let current_version = self.p.get_resource_schema_version(resource_type)?;
        return Ok(state_from_msgpack(&new.state, new.private, current_version)?);
    }

    pub async fn delete(&self, resource_type: &str, state: ResourceState) -> Result<(), anyhow::Error> {
        let state = self.maybe_upgrade_state(resource_type, state).await?;
        check_schema(&self.state_schemask(resource_type)?, &state.state)?;
        let prior_mp = state_to_msgpack(&state)?;
        let null_mp = null_msgpack();
        let plan =
            self.p.plan(&resource_type, prior_mp.clone(), null_mp.clone(), null_mp.clone(), state.private).await?;
        self.p.apply(&resource_type, prior_mp, plan.planned_state, null_mp, plan.planned_private).await?;
        return Ok(());
    }
}

fn cty_type_to_maskoid(type_json: &serde_json::Value) -> Result<Maskoid, anyhow::Error> {
    match type_json {
        serde_json::Value::String(s) => match s.as_str() {
            "string" => return Ok(Maskoid::string()),
            "number" => return Ok(Maskoid::float()),
            "bool" => return Ok(Maskoid::bool()),
            "dynamic" => return Ok(Maskoid::any()),
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
                    let mut fields = BTreeMap::new();
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

/// Wrap an object maskoid in the collection implied by a nesting mode.
fn nest_maskoid(nesting: SchemaNesting, inner: Maskoid) -> Maskoid {
    match nesting {
        SchemaNesting::Single | SchemaNesting::Group => return inner,
        SchemaNesting::List => return Maskoid::list(inner),
        SchemaNesting::Set => return Maskoid::set(inner),
        SchemaNesting::Map => return Maskoid::string_map(inner),
    }
}

/// Build a record maskoid for a block.  With `include_computed_only` false
/// (params), pure-computed attributes are omitted since the user cannot set them;
/// with it true (state), they are included.  Nested blocks are optional because an
/// absent block has a well-defined meaning (empty collection or null), except in
/// params when the provider requires at least one.
///
/// Terraform properties that the maskoid shape can't express (computed defaults,
/// sensitive, deprecation, collection item limits, etc.) are attached to each
/// field's maskoid as metadata.  Only properties that are set are included.
fn block_to_schemask_record(
    attrs: &[SchemaAttr],
    blocks: &[SchemaNestedBlock],
    description: &str,
    include_computed_only: bool,
) -> Result<Maskoid, anyhow::Error> {
    let mut fields = BTreeMap::new();
    for attr in attrs {
        if !include_computed_only && attr.pure_computed() {
            continue;
        }
        let inner = match &attr.type_ {
            SchemaAttrType::Cty(cty) => {
                cty_type_to_maskoid(
                    &serde_json::from_slice(
                        &cty.type_json,
                    ).with_context(|| format!("Error parsing cty type for attribute [{}]", attr.name))?,
                ).with_context(|| format!("Error converting cty type for attribute [{}]", attr.name))?
            },
            SchemaAttrType::Nested(nested) => {
                nest_maskoid(
                    nested.nesting,
                    block_to_schemask_record(
                        &nested.attrs,
                        &[],
                        "",
                        include_computed_only,
                    ).with_context(|| format!("Error converting nested attribute [{}]", attr.name))?,
                )
            },
        };
        let mut maskoid = if attr.required && !attr.optional {
            inner
        } else {
            Maskoid::option(inner)
        };
        let mut metadata = serde_json::Map::new();
        for (key, set) in [
            // Pure-computed attributes only appear in state, so `computed` there is implied.
            // In params every computed attribute is optional+computed, meaning the provider
            // picks a value when omitted (rather than it being null).
            ("computed", attr.computed && !include_computed_only),
            ("sensitive", attr.sensitive),
            ("write_only", attr.write_only),
            ("deprecated", attr.deprecated),
        ] {
            if set {
                metadata.insert(key.to_string(), serde_json::Value::Bool(true));
            }
        }
        if !attr.deprecation_message.is_empty() {
            metadata.insert(
                "deprecation_message".to_string(),
                serde_json::Value::String(attr.deprecation_message.clone()),
            );
        }
        if !metadata.is_empty() {
            *maskoid.metadata_mut() = Some(serde_json::Value::Object(metadata));
        }
        let mut field = MaskoidField::new(maskoid);
        if !attr.description.is_empty() {
            field = field.with_description(attr.description.clone());
        }
        fields.insert(attr.name.clone(), field);
    }
    for block in blocks {
        let inner =
            block_to_schemask_record(
                &block.block.attrs,
                &block.block.blocks,
                &block.block.description,
                include_computed_only,
            ).with_context(|| format!("Error converting nested block [{}]", block.name))?;
        let nested = nest_maskoid(block.nesting, inner);
        let mut maskoid = if !include_computed_only && block.min_items >= 1 && block.nesting != SchemaNesting::Group {
            nested
        } else {
            Maskoid::option(nested)
        };
        let mut metadata = serde_json::Map::new();
        match block.nesting {
            // At most one by construction, and at least one is expressed by the field not
            // being optional.
            SchemaNesting::Single | SchemaNesting::Group => { },
            SchemaNesting::List | SchemaNesting::Set | SchemaNesting::Map => {
                if block.min_items != 0 {
                    metadata.insert("min_items".to_string(), serde_json::Value::from(block.min_items));
                }
                if block.max_items != 0 {
                    metadata.insert("max_items".to_string(), serde_json::Value::from(block.max_items));
                }
            },
        }
        if block.block.deprecated {
            metadata.insert("deprecated".to_string(), serde_json::Value::Bool(true));
        }
        if !block.block.deprecation_message.is_empty() {
            metadata.insert(
                "deprecation_message".to_string(),
                serde_json::Value::String(block.block.deprecation_message.clone()),
            );
        }
        if !metadata.is_empty() {
            *maskoid.metadata_mut() = Some(serde_json::Value::Object(metadata));
        }
        let mut field = MaskoidField::new(maskoid);
        if !block.block.description.is_empty() {
            field = field.with_description(block.block.description.clone());
        }
        fields.insert(block.name.clone(), field);
    }
    let mut record = Maskoid::record(fields);
    if !description.is_empty() {
        record = record.with_description(description);
    }
    return Ok(record);
}

fn state_to_msgpack(state: &ResourceState) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    json_to_msgpack(&state.state, &mut buf)?;
    return Ok(buf);
}

fn state_from_msgpack(
    new_state_mp: &[u8],
    private: Vec<u8>,
    schema_version: i64,
) -> Result<ResourceState, anyhow::Error> {
    if new_state_mp.is_empty() {
        return Ok(ResourceState {
            state: serde_json::Value::Null,
            schema_version: schema_version,
            private: private,
        });
    }
    let mut rd = &new_state_mp[..];
    return Ok(ResourceState {
        state: msgpack_to_json(
            rmpv::decode::read_value(&mut rd).context("Error decoding resource state")?,
        ).context("Error converting resource state messagepack to json")?,
        schema_version: schema_version,
        private: private,
    });
}

#[cfg(test)]
mod tests {
    use {
        anyhow::Context,
        crate::{
            ExTerra,
            Params,
            Provider,
            ResourceState,
            encoding::{
                SchemaAttr,
                SchemaAttrType,
                SchemaAttrTypeCty,
                SchemaBlock,
                SchemaNestedBlock,
                SchemaNesting,
                UNKNOWN_BYTES,
                encode_block,
                msgpack_to_json,
                proposed_new_block,
            },
        },
        serde_json::json,
        std::path::{
            Path,
            PathBuf,
        },
        tempfile::TempDir,
    };

    const RESOURCE_TYPE: &str = "local_file";

    /// The same `local` provider built for protocol 5 and protocol 6; every provider
    /// test runs against both.
    const BINARIES: [&str; 2] = ["terraform-provider-local_v2.8.0_x5", "terraform-provider-local_v2.8.0_x6"];

    async fn provider(binary: &str) -> Result<Provider, anyhow::Error> {
        let et = ExTerra::new(None)?;
        return Ok(
            et
                .provider(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(binary), Default::default())
                .await
                .with_context(|| format!("Error starting provider [{}]", binary))?,
        );
    }

    async fn run_create(
        p: &Provider,
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
        for binary in BINARIES {
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("input.txt");
            std::fs::write(&target, "datasource content")?;
            let p = provider(binary).await?;
            let state =
                p
                    .create(
                        DATASOURCE_TYPE,
                        Params(
                            [
                                (
                                    "filename".to_string(),
                                    serde_json::Value::String(target.to_str().unwrap().to_string()),
                                ),
                            ]
                                .into_iter()
                                .collect(),
                        ),
                    )
                    .await?;
            assert_eq!(state.state["content"], "datasource content");
        }
        return Ok(());
    }

    #[tokio::test]
    async fn test_create_writes_file() -> anyhow::Result<()> {
        for binary in BINARIES {
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("hello.txt");
            let p = provider(binary).await?;
            run_create(&p, &target, "hello exterra").await?;
            assert!(target.exists(), "managed file was not created");
            assert_eq!(std::fs::read_to_string(&target)?, "hello exterra");
        }
        return Ok(());
    }

    #[tokio::test]
    async fn test_modify_requires_replace_errors() -> anyhow::Result<()> {
        for binary in BINARIES {
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("hello.txt");
            let p = provider(binary).await?;
            let state = run_create(&p, &target, "original content").await?;
            let params =
                Params(
                    [
                        (format!("filename"), serde_json::Value::String(target.to_str().unwrap().to_string())),
                        (format!("content"), serde_json::Value::String(format!("updated content"))),
                    ]
                        .into_iter()
                        .collect(),
                );
            let plan = p.plan_modify("local_file", state.clone(), params.clone()).await?;
            assert_eq!(plan.requires_replace, vec![vec!["content".to_string()]]);
            let err =
                p.modify("local_file", state, params).await.expect_err("modify with ForceNew change should fail");
            let rr = err.downcast_ref::<crate::RequiresReplace>().expect("typed RequiresReplace error");
            assert_eq!(rr.paths, vec![vec!["content".to_string()]]);
        }
        return Ok(());
    }

    #[tokio::test]
    async fn test_modify_omitted_param_is_null_not_prior() -> anyhow::Result<()> {
        for binary in BINARIES {
            // `content` is ForceNew.  Omitting it from params must mean "null", not "keep the
            // prior value", so the provider should see a change that requires replacement and
            // modify should refuse.
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("hello.txt");
            let p = provider(binary).await?;
            let state = run_create(&p, &target, "original content").await?;
            let err =
                p
                    .modify(
                        RESOURCE_TYPE,
                        state,
                        Params(
                            [
                                (
                                    "filename".to_string(),
                                    serde_json::Value::String(target.to_str().unwrap().to_string()),
                                ),
                            ]
                                .into_iter()
                                .collect(),
                        ),
                    )
                    .await
                    .expect_err("omitting a ForceNew param should require replacement");
            assert!(err.to_string().contains("deleted and recreated"), "unexpected error: {}", err);
        }
        return Ok(());
    }

    #[tokio::test]
    async fn test_refresh_and_private_roundtrip() -> anyhow::Result<()> {
        for binary in BINARIES {
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("hello.txt");
            let p = provider(binary).await?;
            let state = run_create(&p, &target, "refresh me").await?;

            // State must survive a JSON round trip, including the private bytes field.
            let json = serde_json::to_string(&state)?;
            let state: ResourceState = serde_json::from_str(&json)?;
            let refreshed = p.refresh(RESOURCE_TYPE, state).await?;
            assert_eq!(refreshed.state["content"], "refresh me");

            // Deleting the file out from under the provider makes refresh report it gone.
            std::fs::remove_file(&target)?;
            let gone = p.refresh(RESOURCE_TYPE, refreshed).await?;
            assert!(gone.state.is_null(), "expected null state after external delete, got {}", gone.state);
        }
        return Ok(());
    }

    #[tokio::test]
    async fn test_delete_removes_file() -> anyhow::Result<()> {
        for binary in BINARIES {
            let work_dir = TempDir::new()?;
            let target = work_dir.path().join("hello.txt");
            let p = provider(binary).await?;
            let state = run_create(&p, &target, "to be deleted").await?;
            assert!(target.exists(), "file should exist before delete");
            p.delete(RESOURCE_TYPE, state).await?;
            assert!(!target.exists(), "managed file should have been deleted");
        }
        return Ok(());
    }

    /// `kill -0` reports whether a pid exists without signalling it.  Used instead of
    /// `/proc` because sandboxes may mount a `/proc` from a different pid namespace.
    fn pid_alive(pid: u32) -> bool {
        return std::process::Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("kill should be runnable")
            .success();
    }

    #[tokio::test]
    async fn test_provider_process_exits_on_drop() -> anyhow::Result<()> {
        for binary in BINARIES {
            let p = provider(binary).await?;
            let pid = p.process_id();
            assert!(pid_alive(pid), "provider should be running");
            drop(p);

            // Drop kills and reaps the child, so the pid must be gone once drop returns.
            assert!(!pid_alive(pid), "provider process still running after drop");
        }
        return Ok(());
    }

    fn cty(name: &str, type_: &str, required: bool, optional: bool, computed: bool) -> SchemaAttr {
        return SchemaAttr {
            name: name.to_string(),
            required: required,
            optional: optional,
            computed: computed,
            sensitive: false,
            write_only: false,
            deprecated: false,
            deprecation_message: String::new(),
            description: String::new(),
            type_: SchemaAttrType::Cty(
                SchemaAttrTypeCty { type_json: serde_json::to_vec(&json!(type_)).unwrap() },
            ),
        };
    }

    fn decode(mp: &[u8]) -> serde_json::Value {
        let mut rd = mp;
        return msgpack_to_json(rmpv::decode::read_value(&mut rd).unwrap()).unwrap();
    }

    #[test]
    fn test_encode_nested_blocks() -> anyhow::Result<()> {
        let block = SchemaBlock {
            attrs: vec![cty("name", "string", true, false, false), cty("id", "string", false, false, true)],
            blocks: vec![SchemaNestedBlock {
                name: "single".to_string(),
                nesting: SchemaNesting::Single,
                min_items: 0,
                max_items: 0,
                block: SchemaBlock {
                    attrs: vec![cty("a", "string", false, true, false)],
                    blocks: vec![],
                    ..Default::default()
                },
            }, SchemaNestedBlock {
                name: "group".to_string(),
                nesting: SchemaNesting::Group,
                min_items: 0,
                max_items: 0,
                block: SchemaBlock {
                    attrs: vec![cty("a", "string", false, true, false)],
                    blocks: vec![],
                    ..Default::default()
                },
            }, SchemaNestedBlock {
                name: "list".to_string(),
                nesting: SchemaNesting::List,
                min_items: 0,
                max_items: 0,
                block: SchemaBlock {
                    attrs: vec![cty("a", "string", false, true, false), cty("c", "string", false, false, true)],
                    blocks: vec![],
                    ..Default::default()
                },
            }, SchemaNestedBlock {
                name: "map".to_string(),
                nesting: SchemaNesting::Map,
                min_items: 0,
                max_items: 0,
                block: SchemaBlock {
                    attrs: vec![cty("a", "string", false, true, false)],
                    blocks: vec![],
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let serde_json::Value::Object(values) = json!({
            "name": "x",
            "list":[{
                "a": "one"
            }],
            "map": {
                "k": {
                    "a": "v"
                }
            },
        }) else {
            unreachable!();
        };

        // Config: absent blocks take Terraform's absent-block shapes, computed stays null.
        let mut buf = Vec::new();
        encode_block(&block.attrs, &block.blocks, &values, false, &mut buf)?;
        assert_eq!(decode(&buf), json!({
            "name": "x",
            "id": null,
            "single": null,
            "group": {
                "a": null
            },
            "list":[{
                "a": "one",
                "c": null
            }],
            "map": {
                "k": {
                    "a": "v"
                }
            },
        }));
        assert!(!buf.windows(3).any(|w| w == UNKNOWN_BYTES), "config must not contain unknowns");

        // Proposed: pure-computed attrs become the unknown sentinel, including inside
        // nested blocks (`id` at the top and `c` inside the list element).
        let mut buf = Vec::new();
        encode_block(&block.attrs, &block.blocks, &values, true, &mut buf)?;
        assert_eq!(buf.windows(3).filter(|w| *w == UNKNOWN_BYTES).count(), 2);
        return Ok(());
    }

    #[test]
    fn test_proposed_new_follows_terraform_rule() -> anyhow::Result<()> {
        let block = SchemaBlock {
            attrs: vec![
                cty("req", "string", true, false, false),
                cty("opt", "string", false, true, false),
                cty("opt_computed", "string", false, true, true),
                cty("computed", "string", false, false, true),
            ],
            blocks: vec![SchemaNestedBlock {
                name: "items".to_string(),
                nesting: SchemaNesting::List,
                min_items: 0,
                max_items: 0,
                block: SchemaBlock {
                    attrs: vec![cty("a", "string", false, true, false), cty("oc", "string", false, true, true)],
                    blocks: vec![],
                    ..Default::default()
                },
            }],
            ..Default::default()
        };
        let serde_json::Value::Object(prior) = json!({
            "req": "old",
            "opt": "old-opt",
            "opt_computed": "old-oc",
            "computed": "old-c",
            "items":[{
                "a": "old-a",
                "oc": "old-item-oc"
            }],
        }) else {
            unreachable!();
        };
        let serde_json::Value::Object(config) = json!({
            "req": "new",
            "items":[{
                "a": "new-a"
            }],
        }) else {
            unreachable!();
        };
        let proposed = proposed_new_block(&block.attrs, &block.blocks, Some(&prior), &config);

        // `req`: config wins.  `opt`: omitted non-computed is absent (null), not prior.
        // `opt_computed`: omitted optional+computed carries the prior value forward.
        // `computed`: pure computed is left absent so the encoder emits unknown. `items`:
        // equal-length lists pair elements by index.
        assert_eq!(serde_json::Value::Object(proposed), json!({
            "req": "new",
            "opt_computed": "old-oc",
            "items":[{
                "a": "new-a",
                "oc": "old-item-oc"
            }],
        }));
        return Ok(());
    }
}
