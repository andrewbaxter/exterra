use {
    crate::encoding::SchemaAttr,
    rustls::crypto::CryptoProvider,
    std::sync::Arc,
};

#[derive(Clone)]
pub(crate) struct ProviderShared {
    pub(crate) crypto: Arc<CryptoProvider>,
    pub(crate) own_pub_pem: String,
    pub(crate) own_pub_der: Vec<u8>,
    pub(crate) own_priv_der: Vec<u8>,
}

pub(crate) struct PlanResult {
    pub planned_state: Vec<u8>,
    pub planned_private: Vec<u8>,
    /// True when the provider requires destroy-then-recreate for this change.
    pub requires_replace: bool,
}

pub(crate) trait ProviderInnerImpl {
    fn list_resource_types(&self) -> Vec<String>;
    fn get_provider_schema_attrs(&self) -> Vec<SchemaAttr>;
    fn get_resource_schema(&self, type_: &str) -> Result<Vec<SchemaAttr>, anyhow::Error>;
    fn get_datasource_schema(&self, type_: &str) -> Result<Vec<SchemaAttr>, anyhow::Error>;
    async fn read_datasource(
        &mut self,
        type_: &str,
        config: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error>;
    async fn read(
        &mut self,
        resource_type: &str,
        current_state: Vec<u8>,
        private: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error>;
    async fn import(
        &mut self,
        resource_type: &str,
        id: &str,
    ) -> Result<Vec<u8>, anyhow::Error>;
    async fn plan(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        proposed_new_state: Vec<u8>,
        config: Vec<u8>,
        prior_private: Vec<u8>,
    ) -> Result<PlanResult, anyhow::Error>;
    async fn apply(
        &mut self,
        resource_type: &str,
        prior_state: Vec<u8>,
        planned_state: Vec<u8>,
        config: Vec<u8>,
        planned_private: Vec<u8>,
    ) -> Result<Vec<u8>, anyhow::Error>;
}
