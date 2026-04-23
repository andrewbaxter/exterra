use {
    crate::{
        encoding::{
            SchemaAttr,
            build_config_msgpack,
        },
        provider::v_::{
            ProviderInnerImpl,
            PlanResult,
        },
    },
    std::{
        collections::HashMap,
        process::Child,
    },
    tonic::transport::Channel,
};

pub mod proto {
    #![allow(dead_code)]

    tonic::include_proto!("tfplugin6");
}

fn dv(mp: Vec<u8>) -> proto::DynamicValue {
    proto::DynamicValue {
        msgpack: mp,
        json: vec![],
    }
}

fn extract(dv: Option<proto::DynamicValue>) -> Vec<u8> {
    dv.map(|d| if !d.msgpack.is_empty() {
        d.msgpack
    } else {
        d.json
    }).unwrap_or_default()
}

fn check_diags(diags: &[proto::Diagnostic]) -> Result<(), anyhow::Error> {
    let errs: Vec<_> = diags.iter().filter(|d| d.severity == proto::diagnostic::Severity::Error as i32).collect();
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

fn block_attrs(block: Option<&proto::schema::Block>) -> Vec<SchemaAttr> {
    return block.map(|b| {
        b.attributes.iter().map(|a| SchemaAttr {
            name: a.name.clone(),
            required: a.required,
            optional: a.optional,
            computed: a.computed,
            type_: a.r#type.clone(),
        }).collect()
    }).unwrap_or_default();
}

pub(crate) struct ProviderInner {
    c: proto::provider_client::ProviderClient<Channel>,
    schema: proto::get_provider_schema::Response,
    _process: Child,
}

impl ProviderInner {
    pub(crate) async fn new(
        _process: Child,
        provider_config: serde_json::Map<String, serde_json::Value>,
        channel: Channel,
    ) -> Result<Self, anyhow::Error> {
        let mut c = proto::provider_client::ProviderClient::new(channel);
        let schema = c.get_provider_schema(proto::get_provider_schema::Request {}).await?.into_inner();
        check_diags(&schema.diagnostics)?;
        let attrs = schema.provider.as_ref().map(|s| block_attrs(s.block.as_ref()));
        let provider_config_mp = if provider_config.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_map_len(&mut buf, 0)?;
            buf
        } else {
            build_config_msgpack(&attrs.unwrap_or_default(), &provider_config, false)?
        };
        let resp = c.configure_provider(proto::configure_provider::Request {
            terraform_version: "1.0.0".into(),
            config: Some(dv(provider_config_mp)),
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(Self {
            c: c,
            schema: schema,
            _process: _process,
        });
    }
}

impl ProviderInnerImpl for ProviderInner {
    fn list_resource_types(&self) -> Vec<String> {
        let mut types: Vec<String> = self.schema.resource_schemas.keys().cloned().collect();
        types.sort();
        return types;
    }

    fn get_provider_schema_attrs(&self) -> Vec<SchemaAttr> {
        return block_attrs(self.schema.provider.as_ref().and_then(|s| s.block.as_ref()));
    }

    fn get_resource_schema(&self, type_: &str) -> Result<Vec<SchemaAttr>, anyhow::Error> {
        return Ok(
            block_attrs(
                self
                    .schema
                    .resource_schemas
                    .get(type_)
                    .ok_or_else(
                        || anyhow::anyhow!("Provider has no schema for resource [{}], is the name correct?", type_),
                    )?
                    .block
                    .as_ref(),
            ),
        );
    }

    fn get_datasource_schema(&self, type_: &str) -> Result<Vec<SchemaAttr>, anyhow::Error> {
        return Ok(
            block_attrs(
                self
                    .schema
                    .data_source_schemas
                    .get(type_)
                    .ok_or_else(
                        || anyhow::anyhow!("Provider has no schema for datasource [{}], is the name correct?", type_),
                    )?
                    .block
                    .as_ref(),
            ),
        );
    }

    fn get_resource_schema_version(&self, type_: &str) -> i64 {
        return self
            .schema
            .resource_schemas
            .get(type_)
            .and_then(|s| s.block.as_ref())
            .map(|b| b.version)
            .unwrap_or(0);
    }

    async fn read_datasource(
        &mut self,
        type_: &str,
        config: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.read_data_source(proto::read_data_source::Request {
            type_name: type_.into(),
            config: Some(dv(config)),
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.state));
    }

    async fn read(
        &mut self,
        resource_type: &str,
        current_state: Vec<u8>,
        private: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.read_resource(proto::read_resource::Request {
            type_name: resource_type.into(),
            current_state: Some(dv(current_state)),
            private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.new_state));
    }

    async fn import(
        &mut self,
        resource_type: &str,
        id: &str,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.import_resource_state(proto::import_resource_state::Request {
            type_name: resource_type.into(),
            id: id.into(),
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        let imported = resp.imported_resources.into_iter().next()
            .ok_or_else(|| anyhow::anyhow!("Provider returned no imported resources for [{}] id [{}]", resource_type, id))?;
        return Ok(extract(imported.state));
    }

    async fn plan(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> Result<PlanResult, anyhow::Error> {
        let resp = self.c.plan_resource_change(proto::plan_resource_change::Request {
            type_name: resource_type.into(),
            prior_state: Some(dv(prior_state)),
            proposed_new_state: Some(dv(proposed_new_state)),
            config: Some(dv(config)),
            prior_private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(PlanResult {
            planned_state: extract(resp.planned_state),
            planned_private: resp.planned_private,
            requires_replace: !resp.requires_replace.is_empty(),
        });
    }

    async fn apply(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.apply_resource_change(proto::apply_resource_change::Request {
            type_name: resource_type.into(),
            prior_state: Some(dv(prior_state)),
            planned_state: Some(dv(planned_state)),
            config: Some(dv(config)),
            planned_private,
            ..Default::default()
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.new_state));
    }

    async fn upgrade_resource_state(
        &mut self,
        resource_type: &str,
        version: i64,
        raw_state_json: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let resp = self.c.upgrade_resource_state(proto::upgrade_resource_state::Request {
            type_name: resource_type.into(),
            version,
            raw_state: Some(proto::RawState {
                json: raw_state_json,
                flatmap: HashMap::new(),
            }),
        }).await?.into_inner();
        check_diags(&resp.diagnostics)?;
        return Ok(extract(resp.upgraded_state));
    }
}
