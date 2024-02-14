use clap::{Args, Parser, Subcommand};

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
    AddRelationship(AddRelationshipArgs),
    // Create a new phrase (degree 1 proof)
    CreatePhrase(CreatePhrase),
    // Prove a degree of separation
    ProveSeparation(ProveSeparationArgs),
    // View the OID's of proofs the user can build from
    AvailableProofs,
    // Get account details
    GetAccount,
    ProveAll,
    MyDegrees,
}

#[derive(Args)]
struct RegisterAccountArgs {
    username: Option<String>,
}

#[derive(Args)]
struct AddRelationshipArgs {
    username: Option<String>,
}

#[derive(Args)]
struct CreatePhrase {
    phrase: Option<String>,
}

#[derive(Args)]
struct ProveSeparationArgs {
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
        Commands::AddRelationship(cmd) => {
            controllers::add_relationship(cmd.username.clone().unwrap()).await
        }
        Commands::CreatePhrase(cmd) => {
            controllers::create_new_phrase(cmd.phrase.clone().unwrap()).await
        }
        Commands::ProveSeparation(cmd) => {
            controllers::prove_separation_degree(cmd.username.clone().unwrap()).await
        }
        Commands::AvailableProofs => controllers::get_available_proofs().await,
        Commands::GetAccount => controllers::account_details(),
        Commands::ProveAll => controllers::prove_all_available().await,
        Commands::MyDegrees => controllers::get_my_proofs().await,
    }
}
