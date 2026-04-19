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
    std::process::Child,
    tonic::transport::Channel,
};

pub mod proto {
    #![allow(dead_code)]

    tonic::include_proto!("tfplugin5");
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
    block.map(|b| {
        b.attributes.iter().map(|a| SchemaAttr {
            name: a.name.clone(),
            required: a.required,
            optional: a.optional,
            computed: a.computed,
        }).collect()
    }).unwrap_or_default()
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
        let schema = c.get_schema(proto::get_provider_schema::Request {}).await?.into_inner();
        check_diags(&schema.diagnostics)?;
        let attrs = schema.provider.as_ref().map(|s| block_attrs(s.block.as_ref()));
        let provider_config_mp = if provider_config.is_empty() {
            let mut buf = Vec::new();
            rmp::encode::write_map_len(&mut buf, 0)?;
            buf
        } else {
            build_config_msgpack(&attrs.unwrap_or_default(), &provider_config, false)?
        };
        let resp = c.configure(proto::configure::Request {
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
}
