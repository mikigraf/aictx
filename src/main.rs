#![forbid(unsafe_code)]

use clap::Parser;

use aictx::{
    binary::{BinaryOverrides, set_binary_overrides},
    cli::Cli,
    commands,
    config::AppPaths,
};

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{}", error.render_for_terminal());
            std::process::exit(error.exit_code().into());
        }
    }
}

fn run() -> aictx::Result<i32> {
    let cli = Cli::parse();
    set_binary_overrides(BinaryOverrides {
        claude: cli.claude_bin.clone(),
        codex: cli.codex_bin.clone(),
    })?;
    let paths = AppPaths::discover(cli.root.as_deref())?;
    commands::execute(cli, &paths)
}
