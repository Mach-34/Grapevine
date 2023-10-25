mod controllers;

use std::io::Read;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // Generate public parameters
    Params(ParamsArgs)
}

#[derive(Args)]
struct ParamsArgs {
    r1cs: Option<String>,
    output: Option<String>,
}


/**
 * CLI for generating nova-scotia public parameters file
 * `phrasedos_params_gen <phrase>`
 */
pub fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Params(cmd) => {
            controllers::params::gen_params(
                cmd.r1cs.clone().unwrap(),
                cmd.output.clone().unwrap()
            );
        }
    }
}