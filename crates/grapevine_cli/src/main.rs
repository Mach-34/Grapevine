use clap::{Args, Parser, Subcommand};

mod account;
mod artifacts;
mod controllers;
mod errors;
mod utils;

pub const SERVER_URL: &str = "http://localhost:8000";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    // dummy health check command
    Health,
    // Create a new Grapevine Account
    RegisterAccount(RegisterAccountArgs),
    // Add yourself as a connection to another Grapevine Account
    AddConnection(AddConnectionArgs),
    TestProofCompression,
}

// #[derive(Args)]
// struct ParamsArgs {
//     r1cs: Option<String>,
//     output: Option<String>,
// }

#[derive(Args)]
struct RegisterAccountArgs {
    username: Option<String>,
}

#[derive(Args)]
struct AddConnectionArgs {
    username: Option<String>,
}

/**
 * CLI for Grapevine
 */
#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    _ = match &cli.command {
        // Commands::Params(cmd) => {
        //     controllers::gen_params(cmd.r1cs.clone().unwrap(), cmd.output.clone().unwrap())
        // }
        Commands::Health => controllers::health().await,
        Commands::RegisterAccount(cmd) => {
            controllers::register(cmd.username.clone().unwrap()).await
        }
        Commands::AddConnection(cmd) => {
            controllers::add_connection(cmd.username.clone().unwrap()).await
        }
        Commands::TestProofCompression => controllers::test_proof_compression(),
    }

    // match &cli.command {
    //     Commands::Params(cmd) => {
    //         controllers::gen_params(cmd.r1cs.clone().unwrap(), cmd.output.clone().unwrap())
    //     }]
    //     Commands::ProveSecret(cmd) => controllers::degree_0_proof(
    //         cmd.secret.clone().unwrap(),
    //         cmd.username.clone().unwrap(),
    //         cmd.output_dir.clone().unwrap(),
    //         cmd.public_params_path.clone().unwrap(),
    //         cmd.r1cs_path.clone().unwrap(),
    //         cmd.wc_path.clone().unwrap(),
    //     ),
    //     Commands::ProveSeparation(cmd) => {
    //         // parse degrees of separation
    //         let degrees = cmd.degrees.clone().unwrap().parse::<usize>().unwrap();
    //         // prove
    //         controllers::degree_n_proof(
    //             degrees,
    //             cmd.previous_username.clone().unwrap(),
    //             cmd.username.clone().unwrap(),
    //             cmd.proof_path.clone().unwrap(),
    //             cmd.output_dir.clone().unwrap(),
    //             cmd.public_params_path.clone().unwrap(),
    //             cmd.r1cs_path.clone().unwrap(),
    //             cmd.wc_path.clone().unwrap(),
    //         )
    //     }
    //     Commands::Verify(cmd) => {
    //         // parse degrees of separation
    //         let degrees = cmd.degrees.clone().unwrap().parse::<usize>().unwrap();
    //         // verify
    //         controllers::verify_proof(
    //             degrees,
    //             cmd.proof_path.clone().unwrap(),
    //             cmd.public_params_path.clone().unwrap(),
    //         );
    //     }
    // }
}
