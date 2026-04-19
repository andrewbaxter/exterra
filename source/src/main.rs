mod encoding;
mod operations;
mod provider;

use std::path::PathBuf;

use aargvark::{vark, Aargvark};

#[derive(Aargvark)]
struct CreateCommand {
    /// Path to the terraform provider binary.
    provider: PathBuf,
    /// Path to the input JSON file (resource type and desired values).
    input: PathBuf,
    /// Path to write the output state JSON file.
    output_state: PathBuf,
}

#[derive(Aargvark)]
struct ModifyCommand {
    /// Path to the terraform provider binary.
    provider: PathBuf,
    /// Path to the input JSON file (new desired values).
    input: PathBuf,
    /// Path to the current state JSON file.
    state: PathBuf,
    /// Path to write the output state JSON file.
    output_state: PathBuf,
}

#[derive(Aargvark)]
struct DeleteCommand {
    /// Path to the terraform provider binary.
    provider: PathBuf,
    /// Path to the state JSON file.
    state: PathBuf,
}

#[derive(Aargvark)]
enum Command {
    Create(CreateCommand),
    Modify(ModifyCommand),
    Delete(DeleteCommand),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install the ring crypto provider for rustls (required by rustls 0.23).
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let command = vark::<Command>();
    match command {
        Command::Create(c) => {
            operations::create(&c.provider, &c.input, &c.output_state).await
        }
        Command::Modify(m) => {
            operations::modify(&m.provider, &m.input, &m.state, &m.output_state).await
        }
        Command::Delete(d) => operations::delete(&d.provider, &d.state).await,
    }
}
