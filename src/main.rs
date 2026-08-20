#![forbid(unsafe_code)]

use clap::Parser;

use aictx::{
    binary::{BinaryOverrides, set_binary_overrides},
    cli::Cli,
    commands,
    config::AppPaths,
};

fn main() {
    let cli = Cli::parse();
    if let Err(error) = set_binary_overrides(BinaryOverrides {
        claude: cli.claude_bin.clone(),
        codex: cli.codex_bin.clone(),
    }) {
        eprintln!("aictx: {}", terminal_safe(&error.to_string()));
        std::process::exit(error.exit_code().into());
    }
    let paths = match AppPaths::discover(cli.root.as_deref()) {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("aictx: {}", terminal_safe(&error.to_string()));
            std::process::exit(error.exit_code().into());
        }
    };

    match commands::execute(cli, &paths) {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("aictx: {}", terminal_safe(&error.to_string()));
            std::process::exit(error.exit_code().into());
        }
    }
}

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control() {
            output.extend(character.escape_default());
        } else {
            output.push(character);
        }
    }
    output
}
