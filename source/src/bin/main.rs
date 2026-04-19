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
enum Command {
    List(ListCommand),
    Create(CreateCommand),
    Modify(ModifyCommand),
    Delete(DeleteCommand),
    Refresh(RefreshCommand),
    Import(ImportCommand),
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let command = vark::<Command>();
    match command {
        Command::List(c) => {
            let p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            println!("{}", serde_json::to_string_pretty(&p.list_resource_types()).unwrap());
        },
        Command::Create(c) => {
            let mut p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            println!("{}", serde_json::to_string_pretty(&p.create(&c.resource_type, c.params.value).await?).unwrap());
        },
        Command::Modify(c) => {
            let mut p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &p.modify(&c.resource_type, c.state.value, c.params.value).await?
                ).unwrap()
            );
        },
        Command::Delete(c) => {
            let mut p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            p.delete(&c.resource_type, c.state.value).await?;
        },
        Command::Refresh(c) => {
            let mut p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &p.refresh(&c.resource_type, c.state.value).await?
                ).unwrap()
            );
        },
        Command::Import(c) => {
            let mut p =
                ExTerra::new()?
                    .provider(&c.provider, c.provider_params.map(|x| x.value).unwrap_or_default())
                    .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &p.import(&c.resource_type, &c.id).await?
                ).unwrap()
            );
        },
    }
    return Ok(());
}
