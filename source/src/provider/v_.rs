use {
    crate::encoding::SchemaBlock,
    rustls::crypto::CryptoProvider,
    std::sync::Arc,
};

#[derive(Clone)]
pub(crate) struct ProviderShared {
    pub(crate) crypto: Arc<CryptoProvider>,
    pub(crate) own_pub_pem: String,
    pub(crate) own_pub_der: Vec<u8>,
    pub(crate) own_priv_der: Vec<u8>,
    /// Host version reported to providers in `ConfigureProvider`.
    pub(crate) terraform_version: String,
}

pub(crate) struct PlanResult {
    pub planned_state: Vec<u8>,
    pub planned_private: Vec<u8>,
    /// True when the provider requires destroy-then-recreate for this change.
    pub requires_replace: Vec<Vec<String>>,
}

/// A resource state as returned by the provider: the msgpack cty value plus the
/// provider's opaque private bytes which must be stored alongside it and handed
/// back on the next request.
pub(crate) struct StateResult {
    pub state: Vec<u8>,
    pub private: Vec<u8>,
}

pub(crate) trait ProviderInnerImpl {
    fn list_resource_types(&self) -> Vec<String>;
    fn list_datasource_types(&self) -> Vec<String>;
    fn process_id(&self) -> u32;
    fn get_provider_schema(&self) -> SchemaBlock;
    fn get_resource_schema(&self, type_: &str) -> Result<SchemaBlock, anyhow::Error>;
    fn get_datasource_schema(&self, type_: &str) -> Result<SchemaBlock, anyhow::Error>;
    fn get_resource_schema_version(&self, type_: &str) -> Result<i64, anyhow::Error>;
    async fn read_datasource(&self, type_: &str, config: Vec<u8>) -> Result<Vec<u8>, anyhow::Error>;
    async fn read(
        &self,
        resource_type: &str,
        current_state: Vec<u8>,
        private: Vec<u8>,
    ) -> Result<StateResult, anyhow::Error>;
    async fn import(&self, resource_type: &str, id: &str) -> Result<StateResult, anyhow::Error>;
    async fn plan(
        &self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> Result<PlanResult, anyhow::Error>;
    async fn apply(
        &self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> Result<StateResult, anyhow::Error>;
    async fn upgrade_resource_state(
        &self,
        resource_type: &str,
        version: i64,
        raw_state_json: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error>;
}
