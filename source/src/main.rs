use std::path::PathBuf;
use aargvark::{
    Aargvark,
    vark,
};

#[derive(Aargvark)]
struct CreateCommand {
    /// Path to the terraform provider binary
    provider: PathBuf,
    /// Path to the input JSON file
    input: PathBuf,
    /// Path to write the output state JSON file
    output_state: PathBuf,
}

#[derive(Aargvark)]
struct ModifyCommand {
    /// Path to the terraform provider binary
    provider: PathBuf,
    /// Path to the input JSON file
    input: PathBuf,
    /// Path to the current state JSON file
    state: PathBuf,
    /// Path to write the output state JSON file
    output_state: PathBuf,
}

#[derive(Aargvark)]
struct DeleteCommand {
    /// Path to the terraform provider binary
    provider: PathBuf,
    /// Path to the state JSON file
    state: PathBuf,
}

#[derive(Aargvark)]
enum Command {
    Create(CreateCommand),
    Modify(ModifyCommand),
    Delete(DeleteCommand),
}

fn main() {
    let command = vark::<Command>();
    match command {
        Command::Create(c) => {
            println!(
                "Create: provider={}, input={}, output_state={}",
                c.provider.display(),
                c.input.display(),
                c.output_state.display()
            );
        }
        Command::Modify(m) => {
            println!(
                "Modify: provider={}, input={}, state={}, output_state={}",
                m.provider.display(),
                m.input.display(),
                m.state.display(),
                m.output_state.display()
            );
        }
        Command::Delete(d) => {
            println!(
                "Delete: provider={}, state={}",
                d.provider.display(),
                d.state.display()
            );
        }
    }
}
