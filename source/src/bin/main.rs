use {
    aargvark::{
        Aargvark,
        traits_impls::AargvarkJson,
        vark,
    },
    exterra::{
        ExTerra,
        Params,
        ResourceState,
    },
    std::path::PathBuf,
};

#[derive(Aargvark)]
struct ListCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
}

#[derive(Aargvark)]
struct CreateCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
    params: AargvarkJson<Params>,
}

#[derive(Aargvark)]
struct ModifyCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
    params: AargvarkJson<Params>,
    state: AargvarkJson<ResourceState>,
}

#[derive(Aargvark)]
struct DeleteCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
    state: AargvarkJson<ResourceState>,
}

#[derive(Aargvark)]
struct RefreshCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
    state: AargvarkJson<ResourceState>,
}

#[derive(Aargvark)]
struct ImportCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
    id: String,
}

#[derive(Aargvark)]
struct ProviderSchemaskCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
}

#[derive(Aargvark)]
struct SchemaskCommand {
    provider: PathBuf,
    provider_params: Option<AargvarkJson<Params>>,
    resource_type: String,
}

#[derive(Aargvark)]
enum Command {
    List(ListCommand),
    Create(CreateCommand),
    Modify(ModifyCommand),
    Delete(DeleteCommand),
    Refresh(RefreshCommand),
    Import(ImportCommand),
    ProviderSchemask(ProviderSchemaskCommand),
    Schemask(SchemaskCommand),
}

#[derive(Aargvark)]
struct Args {
    /// Host version reported to the provider (default `1.0.0`).
    terraform_version: Option<String>,
    command: Command,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = vark::<Args>();
    let et = ExTerra::new(args.terraform_version)?;
    match args.command {
        Command::List(c) => {
            let p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!("{}", serde_json::to_string_pretty(&p.list_resource_types()).unwrap());
        },
        Command::Create(c) => {
            let mut p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!("{}", serde_json::to_string_pretty(&p.create(&c.resource_type, c.params.value).await?).unwrap());
        },
        Command::Modify(c) => {
            let mut p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &p.modify(&c.resource_type, c.state.value, c.params.value).await?
                ).unwrap()
            );
        },
        Command::Delete(c) => {
            let mut p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            p.delete(&c.resource_type, c.state.value).await?;
        },
        Command::Refresh(c) => {
            let mut p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!("{}", serde_json::to_string_pretty(&p.refresh(&c.resource_type, c.state.value).await?).unwrap());
        },
        Command::Import(c) => {
            let mut p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!("{}", serde_json::to_string_pretty(&p.import(&c.resource_type, &c.id).await?).unwrap());
        },
        Command::ProviderSchemask(c) => {
            let p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            println!("{}", serde_json::to_string_pretty(&schemask::Schemask::V1(p.provider_schemask()?)).unwrap());
        },
        Command::Schemask(c) => {
            let p = et.provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default()).await?;
            let mut bindings = std::collections::BTreeMap::new();
            bindings.extend(p.params_schemask(&c.resource_type)?.bindings);
            bindings.extend(p.state_schemask(&c.resource_type)?.bindings);
            println!("{}", serde_json::to_string_pretty(&schemask::Schemask::V1(schemask::latest::SchemaskV1 {
                bindings: bindings,
                default: None,
            })).unwrap());
        },
    }
    return Ok(());
}
