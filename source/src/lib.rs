use {
    crate::{
        encoding::{
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
    serde::{
        Deserialize,
        Serialize,
    },
    std::{
        path::Path,
        sync::Arc,
    },
};

mod encoding;
mod provider;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Params(pub serde_json::Map<String, serde_json::Value>);

#[derive(Debug, Serialize, Deserialize)]
pub struct ResourceState(pub serde_json::Value);

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
        return Ok(Provider { p: provider::new(&self.provider_shared, binary, config.0).await? });
    }
}

impl Provider {
    pub async fn create(&mut self, resource_type: &str, input: Params) -> Result<ResourceState, anyhow::Error> {
        let attrs = self.p.get_resource_schema(resource_type)?;
        let config_mp = build_config_msgpack(&attrs, &input.0, false)?;
        let proposed_mp = build_config_msgpack(&attrs, &input.0, true)?;
        let prior_mp = null_msgpack();
        let plan = self.p.plan(&resource_type, prior_mp.clone(), proposed_mp, config_mp.clone(), vec![]).await?;
        let new_state_mp =
            self.p.apply(&resource_type, prior_mp, plan.planned_state, config_mp, plan.planned_private).await?;
        return Ok(state_from_msgpack(&new_state_mp)?);
    }

    pub async fn modify(
        &mut self,
        resource_type: &str,
        state: ResourceState,
        params: Params,
    ) -> Result<ResourceState, anyhow::Error> {
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
        if let serde_json::Value::Object(prior_map) = state.0 {
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
        return Ok(state_from_msgpack(&new_state_mp)?);
    }

    pub async fn delete(&mut self, resource_type: &str, state: ResourceState) -> Result<(), anyhow::Error> {
        let prior_mp = state_to_msgpack(&state)?;
        let null_mp = null_msgpack();
        let plan = self.p.plan(&resource_type, prior_mp.clone(), null_mp.clone(), null_mp.clone(), vec![]).await?;
        self.p.apply(&resource_type, prior_mp, plan.planned_state, null_mp, plan.planned_private).await?;
        return Ok(());
    }
}

fn state_to_msgpack(state: &ResourceState) -> Result<Vec<u8>, anyhow::Error> {
    let mut buf = Vec::new();
    json_to_msgpack(&state.0, &mut buf)?;
    Ok(buf)
}

fn state_from_msgpack(new_state_mp: &[u8]) -> Result<ResourceState, anyhow::Error> {
    if new_state_mp.is_empty() {
        return Ok(ResourceState(serde_json::Value::Null));
    }
    let mut rd = &new_state_mp[..];
    return Ok(
        ResourceState(
            msgpack_to_json(
                rmpv::decode::read_value(&mut rd).context("Error decoding resource state")?,
            ).context("Error converting resource state messagepack to json")?,
        ),
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
