use {
    crate::{
        encoding::{
            SchemaAttr,
            SchemaAttrType,
            SchemaAttrTypeCty,
            SchemaBlock,
            SchemaNestedBlock,
            SchemaNesting,
        },
        provider::v_::{
            PlanResult,
            ProviderInnerImpl,
            StateResult,
        },
    },
    std::{
        collections::HashMap,
        process::Child,
    },
    tonic::transport::Channel,
};

pub mod proto {
    tonic::include_proto!("tfplugin5");
}

pub(super) fn dv(mp: Vec<u8>) -> proto::DynamicValue {
    return proto::DynamicValue {
        msgpack: mp,
        json: vec![],
    };
}

fn extract(dv: Option<proto::DynamicValue>) -> Vec<u8> {
    return dv.map(|d| if !d.msgpack.is_empty() {
        d.msgpack
    } else {
        d.json
    }).unwrap_or_default();
}

pub(super) fn check_diags(diags: &[proto::Diagnostic]) -> Result<(), anyhow::Error> {
    let mut errs = vec![];
    for d in diags {
        if d.severity == proto::diagnostic::Severity::Error as i32 {
            errs.push(d);
        } else {
            eprintln!("Provider warning: {}: {}", d.summary, d.detail);
        }
    }
    if !errs.is_empty() {
        return Err(
            anyhow::anyhow!(
                "Provider communication resulted in errors:\n{}",
                errs.iter().map(|d| format!("  {}: {}", d.summary, d.detail)).collect::<Vec<_>>().join("\n")
            ),
        );
    }
    return Ok(());
}

pub(super) fn convert_block(block: Option<&proto::schema::Block>) -> Result<SchemaBlock, anyhow::Error> {
    let Some(block) = block else {
        return Ok(SchemaBlock::default());
    };
    let mut blocks = vec![];
    for b in &block.block_types {
        let nesting = match proto::schema::nested_block::NestingMode::try_from(b.nesting) {
            Ok(proto::schema::nested_block::NestingMode::Single) => SchemaNesting::Single,
            Ok(proto::schema::nested_block::NestingMode::List) => SchemaNesting::List,
            Ok(proto::schema::nested_block::NestingMode::Set) => SchemaNesting::Set,
            Ok(proto::schema::nested_block::NestingMode::Map) => SchemaNesting::Map,
            Ok(proto::schema::nested_block::NestingMode::Group) => SchemaNesting::Group,
            _ => {
                return Err(
                    anyhow::anyhow!("Nested block [{}] has unsupported nesting mode {}", b.type_name, b.nesting),
                );
            },
        };
        blocks.push(SchemaNestedBlock {
            name: b.type_name.clone(),
            nesting: nesting,
            min_items: b.min_items,
            max_items: b.max_items,
            block: convert_block(b.block.as_ref())?,
        });
    }
    let mut attrs = vec![];
    for a in &block.attributes {
        // Protocol 5 has no nested attributes; every attribute is a plain cty type.
        let type_ = SchemaAttrType::Cty(SchemaAttrTypeCty { type_json: a.r#type.clone() });
        attrs.push(SchemaAttr {
            name: a.name.clone(),
            required: a.required,
            optional: a.optional,
            computed: a.computed,
            sensitive: a.sensitive,
            write_only: a.write_only,
            deprecated: a.deprecated,
            deprecation_message: a.deprecation_message.clone(),
            description: a.description.clone(),
            type_: type_,
        });
    }
    return Ok(SchemaBlock {
        attrs: attrs,
        blocks: blocks,
        deprecated: block.deprecated,
        deprecation_message: block.deprecation_message.clone(),
        description: block.description.clone(),
    });
}

pub(crate) struct ProviderInner {
    pub(super) c: proto::provider_client::ProviderClient<Channel>,
    pub(super) schema: proto::get_provider_schema::Response,
    pub(super) process: Child,
}

impl ProviderInner {
    fn resource_schema(&self, type_: &str) -> Result<&proto::Schema, anyhow::Error> {
        return self
            .schema
            .resource_schemas
            .get(type_)
            .ok_or_else(|| anyhow::anyhow!("Provider has no schema for resource [{}], is the name correct?", type_));
    }
}

impl Drop for ProviderInner {
    fn drop(&mut self) {
        // The provider has no reason to exit on its own once the gRPC connection goes
        // away, so without this every run leaves a provider process behind.
        if let Err(e) = self.process.kill() {
            eprintln!("Error killing provider process: {}", e);
        }
        if let Err(e) = self.process.wait() {
            eprintln!("Error waiting for provider process to exit: {}", e);
        }
    }
}

impl ProviderInnerImpl for ProviderInner {
    fn list_resource_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.schema.resource_schemas.keys().cloned().collect();
        types.sort();
        return types;
    }

    fn list_datasource_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.schema.data_source_schemas.keys().cloned().collect();
        types.sort();
        return types;
    }

    fn process_id(&self) -> u32 {
        return self.process.id();
    }

    fn get_provider_schema(&self) -> SchemaBlock {
        match convert_block(self.schema.provider.as_ref().and_then(|s| s.block.as_ref())) {
            Ok(b) => return b,
            Err(e) => {
                // Already validated in `new`, so this cannot fail; log in case that changes.
                eprintln!("Error converting provider schema: {}", e);
                return SchemaBlock::default();
            },
        }
    }

    fn get_resource_schema(&self, type_: &str) -> Result<SchemaBlock, anyhow::Error> {
        return convert_block(self.resource_schema(type_)?.block.as_ref());
    }

    fn get_datasource_schema(&self, type_: &str) -> Result<SchemaBlock, anyhow::Error> {
        return convert_block(
            self
                .schema
                .data_source_schemas
                .get(type_)
                .ok_or_else(
                    || anyhow::anyhow!("Provider has no schema for datasource [{}], is the name correct?", type_),
                )?
                .block
                .as_ref(),
        );
    }

    fn get_resource_schema_version(&self, type_: &str) -> Result<i64, anyhow::Error> {
        // `Schema.version` is what Terraform compares against stored state;
        // `Schema.Block.version` is a vestigial duplicate the SDKs leave at zero.
        return Ok(self.resource_schema(type_)?.version);
    }

    async fn read_datasource(&self, type_: &str, config: Vec<u8>) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.clone().read_data_source(proto::read_data_source::Request {
            type_name: type_.into(),
            config: Some(dv(config)),
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.state));
    }

    async fn read(
        &self,
        resource_type: &str,
        current_state: Vec<u8>,
        private: Vec<u8>,
    ) -> Result<StateResult, anyhow::Error> {
        let resp = self.c.clone().read_resource(proto::read_resource::Request {
            type_name: resource_type.into(),
            current_state: Some(dv(current_state)),
            private: private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(StateResult {
            state: extract(resp.new_state),
            private: resp.private,
        });
    }

    async fn import(&self, resource_type: &str, id: &str) -> Result<StateResult, anyhow::Error> {
        let resp = self.c.clone().import_resource_state(proto::import_resource_state::Request {
            type_name: resource_type.into(),
            id: id.into(),
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        let imported =
            resp
                .imported_resources
                .into_iter()
                .next()
                .ok_or_else(
                    || anyhow::anyhow!("Provider returned no imported resources for [{}] id [{}]", resource_type, id),
                )?;
        return Ok(StateResult {
            state: extract(imported.state),
            private: imported.private,
        });
    }

    async fn plan(
        &self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> Result<PlanResult, anyhow::Error> {
        let resp = self.c.clone().plan_resource_change(proto::plan_resource_change::Request {
            type_name: resource_type.into(),
            prior_state: Some(dv(prior_state)),
            proposed_new_state: Some(dv(proposed_new_state)),
            config: Some(dv(config)),
            prior_private: prior_private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(PlanResult {
            planned_state: extract(resp.planned_state),
            planned_private: resp.planned_private,
            requires_replace: resp.requires_replace.iter().map(|p| p.steps.iter().filter_map(|s| match &s.selector {
                Some(proto::attribute_path::step::Selector::AttributeName(n)) => Some(n.clone()),
                Some(proto::attribute_path::step::Selector::ElementKeyString(k)) => Some(k.clone()),
                Some(proto::attribute_path::step::Selector::ElementKeyInt(i)) => Some(i.to_string()),
                None => None,
            }).collect()).collect(),
        });
    }

    async fn apply(
        &self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> Result<StateResult, anyhow::Error> {
        let resp = self.c.clone().apply_resource_change(proto::apply_resource_change::Request {
            type_name: resource_type.into(),
            prior_state: Some(dv(prior_state)),
            planned_state: Some(dv(planned_state)),
            config: Some(dv(config)),
            planned_private: planned_private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(StateResult {
            state: extract(resp.new_state),
            private: resp.private,
        });
    }

    async fn upgrade_resource_state(
        &self,
        resource_type: &str,
        version: i64,
        raw_state_json: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.clone().upgrade_resource_state(proto::upgrade_resource_state::Request {
            type_name: resource_type.into(),
            version: version,
            raw_state: Some(proto::RawState {
                json: raw_state_json,
                flatmap: HashMap::new(),
            }),
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.upgraded_state));
    }
}
