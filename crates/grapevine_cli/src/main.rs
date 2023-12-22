use clap::{Args, Parser, Subcommand};
pub mod utils;
pub mod auth_secret;
pub mod controllers;
pub mod account;

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
    Params(ParamsArgs),
    // Check stored Grapevine Acocunt info
    GetAccount,
    // Create a new Grapevine Account
    CreateAccount(CreateAccountArgs),
    Health,
}

#[derive(Args)]
struct ParamsArgs {
    r1cs: Option<String>,
    output: Option<String>,
}

#[derive(Args)]
struct CreateAccountArgs {
    username: Option<String>,
}

/**
 * CLI for Grapevine
 */
#[tokio::main]
pub async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Params(cmd) => {
            controllers::gen_params(cmd.r1cs.clone().unwrap(), cmd.output.clone().unwrap())
        }
        Commands::GetAccount => controllers::get_account_info(),
        Commands::CreateAccount(cmd) => controllers::make_account(cmd.username.clone().unwrap()),
        Commands::Health => controllers::health().await,
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
