use clap::{Args, Parser, Subcommand};

mod controllers;
mod errors;
mod http;
mod utils;

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
#[command(verbatim_doc_comment)]
enum Commands {
    /// Test the connection to the Grapevine server
    /// usage: `grapevine health`
    #[command(verbatim_doc_comment)]
    Health,
    /// Print the details of your account
    /// usage: `grapevine get-account`
    #[command(verbatim_doc_comment)]
    GetAccount,
    /// Synchronize the local account nonce with expected nonce
    /// usage: `grapevine sync-nonce`
    #[command(verbatim_doc_comment)]
    SyncNonce,
    /// Create a new Grapevine Account
    /// usage: `grapevine register-account <username>`
    #[command(verbatim_doc_comment)]
    RegisterAccount(RegisterAccountArgs),
    /// Add yourself as a connection to another Grapevine user
    /// usage: `grapevine add-relationship <username>`
    #[command(verbatim_doc_comment)]
    AddRelationship(AddRelationshipArgs),
    /// Create a new phrase
    /// usage: `grapevine create-phrase "<phrase>" "<description>"`
    #[command(verbatim_doc_comment)]
    CreatePhrase(CreatePhraseArgs),
    /// Prove knowledege of a phrase
    /// usage: `grapevine prove-phrase "<phrase>" <index>`
    #[command(verbatim_doc_comment)]
    ProvePhrase(ProvePhraseArgs),
    /// Prove all the the new degrees of separation available
    /// usage: `grapevine prove-new`
    #[command(verbatim_doc_comment)]
    ProveNewDegrees,    
    /// Print all of your degrees of separation
    /// usage: `grapevine get-degrees`
    #[command(verbatim_doc_comment)]
    GetDegrees,
    /// Print all phrases you know (1st degree)
    /// usage: `grapevine get-known-phrases`
    #[command(verbatim_doc_comment)]
    GetKnownPhrases,
    /// Get connection count and degree data for a phrase
    /// usage: `grapevine show-connections`
    #[command(verbatim_doc_comment)]
    ShowConnections(ShowConnectionsArgs),
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
struct CreatePhraseArgs {
    phrase: Option<String>,
    description: Option<String>,
}

#[derive(Args)]
struct ProvePhraseArgs {
    index: Option<u32>,
    phrase: Option<String>,
}

#[derive(Args)]
struct ShowConnectionsArgs {
    phrase_index: Option<u32>,
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
        Commands::GetAccount => controllers::account_details().await,
        Commands::SyncNonce => controllers::synchronize_nonce().await,
        Commands::RegisterAccount(cmd) => controllers::register(cmd.username.clone()).await,
        Commands::AddRelationship(cmd) => {
            controllers::add_relationship(cmd.username.clone().unwrap()).await
        }
        Commands::CreatePhrase(cmd) => {
            controllers::create_new_phrase(
                cmd.phrase.clone().unwrap(),
                cmd.description.clone().unwrap(),
            )
            .await
        }
        Commands::ProvePhrase(cmd) => {
            controllers::prove_phrase_knowledge(cmd.phrase.clone().unwrap(), cmd.index.clone().unwrap()).await
        }
        Commands::ProveNewDegrees => controllers::prove_all_available().await,
        Commands::GetDegrees => controllers::get_my_proofs().await,
        Commands::GetKnownPhrases => controllers::get_known_phrases().await,
        Commands::ShowConnections(cmd) => {
            controllers::show_connections(cmd.phrase_index.clone().unwrap()).await
        }
    };

    match result {
        Ok(message) => {
            println!("{}", message);
        }
        Err(e) => {
            println!("Error: {}", e);
        }
    };
}
