use std::path::Path;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::{
    build_config_msgpack, json_to_msgpack, msgpack_to_json, null_msgpack, SchemaAttr,
};
use crate::provider::Provider;

// ── On-disk JSON formats ──────────────────────────────────────────────────────

/// Input file: desired configuration.
///
/// ```json
/// {
///   "type": "local_file",
///   "provider_config": {},
///   "values": { "filename": "/tmp/foo.txt", "content": "hello" }
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct InputFile {
    #[serde(rename = "type")]
    pub resource_type: String,
    #[serde(default)]
    pub provider_config: serde_json::Map<String, Value>,
    pub values: serde_json::Map<String, Value>,
}

/// State file: persisted resource state (used as input and written as output).
///
/// ```json
/// { "type": "local_file", "values": { "id": "...", "filename": "..." } }
/// ```
#[derive(Debug, Serialize, Deserialize)]
pub struct StateFile {
    #[serde(rename = "type")]
    pub resource_type: String,
    pub values: Value,
}

// ── Public entry points ───────────────────────────────────────────────────────

pub async fn create(
    provider_binary: &Path,
    input_path: &Path,
    output_state_path: &Path,
) -> Result<()> {
    let input: InputFile =
        read_json(input_path).context("reading input file")?;

    let mut provider = Provider::launch(provider_binary).await?;

    let attrs = provider.get_resource_schema(&input.resource_type).await?;

    configure_provider(&mut provider, &attrs, &input.provider_config).await?;

    let (config_mp, proposed_mp) = build_config_and_proposed(&attrs, &input.values)?;
    let prior_mp = null_msgpack();

    let plan = provider
        .plan(&input.resource_type, prior_mp.clone(), proposed_mp, config_mp.clone(), vec![])
        .await?;

    let new_state_mp = provider
        .apply(
            &input.resource_type,
            prior_mp,
            plan.planned_state,
            config_mp,
            plan.planned_private,
        )
        .await?;

    write_state(output_state_path, &input.resource_type, &new_state_mp)
}

pub async fn modify(
    provider_binary: &Path,
    input_path: &Path,
    state_path: &Path,
    output_state_path: &Path,
) -> Result<()> {
    let input: InputFile = read_json(input_path).context("reading input file")?;
    let state: StateFile = read_json(state_path).context("reading state file")?;

    let mut provider = Provider::launch(provider_binary).await?;

    let attrs = provider.get_resource_schema(&input.resource_type).await?;

    configure_provider(&mut provider, &attrs, &input.provider_config).await?;

    let prior_mp = state_to_msgpack(&state.values)?;
    let (config_mp, proposed_mp) =
        build_config_and_proposed_with_prior(&attrs, &input.values, &state.values)?;

    let plan = provider
        .plan(
            &input.resource_type,
            prior_mp.clone(),
            proposed_mp,
            config_mp.clone(),
            vec![],
        )
        .await?;

    if plan.requires_replace {
        anyhow::bail!(
            "modifying {} requires resource replacement; delete and recreate it instead",
            input.resource_type
        );
    }

    let new_state_mp = provider
        .apply(
            &input.resource_type,
            prior_mp,
            plan.planned_state,
            config_mp,
            plan.planned_private,
        )
        .await?;

    write_state(output_state_path, &input.resource_type, &new_state_mp)
}

pub async fn delete(
    provider_binary: &Path,
    state_path: &Path,
) -> Result<()> {
    let state: StateFile = read_json(state_path).context("reading state file")?;

    let mut provider = Provider::launch(provider_binary).await?;

    let attrs = provider.get_resource_schema(&state.resource_type).await?;

    // For delete, provider_config comes from the state file's context; we use
    // empty config since we don't have a separate input file here.
    configure_provider(&mut provider, &attrs, &serde_json::Map::new()).await?;

    let prior_mp = state_to_msgpack(&state.values)?;
    let null_mp = null_msgpack();

    let plan = provider
        .plan(
            &state.resource_type,
            prior_mp.clone(),
            null_mp.clone(),
            null_mp.clone(),
            vec![],
        )
        .await?;

    // planned_state should be null after planning a destroy
    provider
        .apply(
            &state.resource_type,
            prior_mp,
            plan.planned_state,
            null_mp,
            plan.planned_private,
        )
        .await?;

    println!("Resource deleted successfully.");
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("opening {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing JSON from {}", path.display()))
}

async fn configure_provider(
    provider: &mut Provider,
    attrs: &[SchemaAttr],
    provider_config: &serde_json::Map<String, Value>,
) -> Result<()> {
    // Encode provider config as msgpack map.  We pass whatever the caller
    // supplied; an empty map is fine for providers that require no config.
    let mp = if provider_config.is_empty() {
        // Encode as an empty msgpack map.
        let mut buf = Vec::new();
        rmp::encode::write_map_len(&mut buf, 0)?;
        buf
    } else {
        build_config_msgpack(attrs, provider_config, false)?
    };
    provider.configure(mp).await
}

/// Build (config_msgpack, proposed_new_state_msgpack) for a create operation.
/// config: user values + null for computed-only.
/// proposed: user values + unknown sentinel for computed-only.
fn build_config_and_proposed(
    attrs: &[SchemaAttr],
    values: &serde_json::Map<String, Value>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let config = build_config_msgpack(attrs, values, false)?;
    let proposed = build_config_msgpack(attrs, values, true)?;
    Ok((config, proposed))
}

/// Like above but for modify: proposed_new_state merges new config values with
/// prior computed values so the provider can detect what changed.
fn build_config_and_proposed_with_prior(
    attrs: &[SchemaAttr],
    new_values: &serde_json::Map<String, Value>,
    prior_values: &Value,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Computed-only attributes (no required/optional flag) are filled in by the
    // provider.  They must appear as the unknown sentinel in proposed_new_state
    // so the provider knows to recompute them.  Copying the prior value would
    // tell the provider "this attr won't change" and suppress the update.
    let computed_only: std::collections::HashSet<&str> = attrs
        .iter()
        .filter(|a| a.computed && !a.optional && !a.required)
        .map(|a| a.name.as_str())
        .collect();

    // Build a merged map: prior optional/required values + new_values override.
    // Computed-only attrs are intentionally omitted so they become unknown.
    let mut merged = serde_json::Map::new();
    if let Value::Object(prior_map) = prior_values {
        for (k, v) in prior_map {
            if !computed_only.contains(k.as_str()) {
                merged.insert(k.clone(), v.clone());
            }
        }
    }
    for (k, v) in new_values {
        merged.insert(k.clone(), v.clone());
    }

    let config = build_config_msgpack(attrs, new_values, false)?;
    let proposed = build_config_msgpack(attrs, &merged, true)?;
    Ok((config, proposed))
}

/// Encode a state JSON value (flat object) as msgpack.
fn state_to_msgpack(state: &Value) -> Result<Vec<u8>> {
    json_to_msgpack(state)
}

/// Decode the provider's new_state msgpack and write it as the state JSON file.
fn write_state(path: &Path, resource_type: &str, new_state_mp: &[u8]) -> Result<()> {
    let values = msgpack_to_json(new_state_mp).context("decoding provider state")?;
    let state = StateFile {
        resource_type: resource_type.to_string(),
        values,
    };
    let json = serde_json::to_string_pretty(&state)?;
    std::fs::write(path, json)
        .with_context(|| format!("writing state to {}", path.display()))?;
    println!("State written to {}", path.display());
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::PathBuf;
    use tempfile::TempDir;

    /// Install the rustls ring crypto provider exactly once per test process.
    fn setup_crypto() {
        static ONCE: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    /// Path to the provider binary relative to the crate root.
    fn provider() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("terraform-provider-local_v2.8.0_x5")
    }

    /// Write a serde_json::Value as a JSON file inside `dir` and return the path.
    fn write_json_file(dir: &TempDir, name: &str, value: &serde_json::Value) -> PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
        path
    }

    /// Run `create`, then return the output state as a parsed Value and keep the
    /// TempDir alive so the managed file path doesn't get cleaned up under us.
    async fn run_create(
        target_file: &Path,
        content: &str,
    ) -> anyhow::Result<(serde_json::Value, TempDir)> {
        let dir = TempDir::new()?;

        let input_path = write_json_file(
            &dir,
            "input.json",
            &json!({
                "type": "local_file",
                "values": {
                    "filename": target_file.to_str().unwrap(),
                    "content": content
                }
            }),
        );

        let state_path = dir.path().join("state.json");
        create(&provider(), &input_path, &state_path).await?;

        let state: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path)?)?;
        Ok((state, dir))
    }

    // ── create ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_writes_file() -> anyhow::Result<()> {
        setup_crypto();
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");

        let (state, _keep) = run_create(&target, "hello exterra").await?;

        // The managed file should exist with the correct content.
        assert!(target.exists(), "managed file was not created");
        assert_eq!(std::fs::read_to_string(&target)?, "hello exterra");

        // State JSON must have the expected shape.
        assert_eq!(state["type"], "local_file");
        assert!(
            state["values"]["id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
            "state.values.id should be a non-empty string"
        );
        assert_eq!(state["values"]["filename"], target.to_str().unwrap());
        assert_eq!(state["values"]["content"], "hello exterra");

        Ok(())
    }

    // ── modify ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_modify_requires_replace_errors() -> anyhow::Result<()> {
        setup_crypto();
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");

        // Create the resource.
        let (initial_state, _keep) = run_create(&target, "original content").await?;

        // Changing `content` is ForceNew on local_file — modify must return an error.
        let json_dir = TempDir::new()?;
        let input_path = write_json_file(
            &json_dir,
            "input.json",
            &json!({
                "type": "local_file",
                "values": {
                    "filename": target.to_str().unwrap(),
                    "content": "updated content"
                }
            }),
        );
        let state_in_path = write_json_file(&json_dir, "state_in.json", &initial_state);
        let state_out_path = json_dir.path().join("state_out.json");

        let err = modify(&provider(), &input_path, &state_in_path, &state_out_path)
            .await
            .expect_err("modify with ForceNew change should fail");

        assert!(
            err.to_string().contains("requires resource replacement"),
            "unexpected error: {err}"
        );

        Ok(())
    }

    // ── delete ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_delete_removes_file() -> anyhow::Result<()> {
        setup_crypto();
        let work_dir = TempDir::new()?;
        let target = work_dir.path().join("hello.txt");

        // 1. Create the resource so there's something to delete.
        let (initial_state, _keep) = run_create(&target, "to be deleted").await?;
        assert!(target.exists(), "file should exist before delete");

        // 2. Write the state to a temp file and call delete.
        let json_dir = TempDir::new()?;
        let state_path = write_json_file(&json_dir, "state.json", &initial_state);

        delete(&provider(), &state_path).await?;

        // The managed file must no longer exist.
        assert!(!target.exists(), "managed file should have been deleted");

        Ok(())
    }
}
