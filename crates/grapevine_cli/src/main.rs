use clap::{Args, Parser, Subcommand};

mod controllers;
mod errors;
mod http;
mod utils;

pub const SERVER_URL: &str = "http://localhost:8000";

///    ______                           _           
///   / ____/________ _____  ___ _   __(_)___  ___  
///  / / __/ ___/ __ `/ __ \/ _ \ | / / / __ \/ _ \
/// / /_/ / /  / /_/ / /_/ /  __/ |/ / / / / /  __/
/// \____/_/   \__,_/ .___/\___/|___/_/_/ /_/\___/  
///                /_/                              
///                                                 
#[derive(Parser)]
#[command(author, version, about, long_about = None, verbatim_doc_comment)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Test the connection to the Grapevine server
    Health,
    /// Create a new Grapevine Account
    RegisterAccount(RegisterAccountArgs),
    // /// Add yourself as a connection to another Grapevine user
    // AddRelationship(AddRelationshipArgs),
    // /// Create a new phrase (degree 1 proof)
    // CreatePhrase(CreatePhrase),
    // /// Print the details of your account
    // GetAccount,
    // /// Prove all the the new degrees of separation available
    // ProveNew,
    // /// Print all of your degrees of separation
    // GetDegrees,
    // /// Manually prove a degree of separation
    // ProveSeparation(ProveSeparationArgs),
    // // View the OID's of proofs the user can build from
    // AvailableProofs,
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

    let result = match &cli.command {
        Commands::Health => controllers::health().await,
        Commands::RegisterAccount(cmd) => {
            controllers::register(cmd.username.clone()).await
        }
        // Commands::AddRelationship(cmd) => {
        //     controllers::add_relationship(cmd.username.clone().unwrap()).await
        // }
        // Commands::CreatePhrase(cmd) => {
        //     controllers::create_new_phrase(cmd.phrase.clone().unwrap()).await
        // }
        // Commands::GetAccount => controllers::account_details(),
        // Commands::ProveNew => controllers::prove_all_available().await,
        // Commands::GetDegrees => controllers::get_my_proofs().await,


        // Commands::ProveSeparation(cmd) => {
        //     controllers::prove_separation_degree(cmd.username.clone().unwrap()).await
        // }
        // Commands::AvailableProofs => controllers::get_available_proofs().await,
    };

    match result {
        Ok(message) => {
            println!("Success: {}", message);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };
}
