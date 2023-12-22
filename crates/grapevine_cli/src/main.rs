use clap::{Args, Parser, Subcommand};

pub (crate) mod crypto;
pub (crate) mod auth_secret;
pub (crate) mod controllers;

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
    // Folded proof of a secret (proof degree = 1)
    ProveSecret(ProveSecretArgs),
    // Folded proof of N degrees of separation from a secret (proof degree > 1)
    ProveSeparation(ProveSeparationArgs),
    // Verify a proof of N degrees of separatoin
    Verify(VerifyArgs),
    // ECDSA
}

#[derive(Args)]
struct ParamsArgs {
    r1cs: Option<String>,
    output: Option<String>,
}

#[derive(Args)]
struct ProveSecretArgs {
    secret: Option<String>,
    username: Option<String>,
    output_dir: Option<String>,
    public_params_path: Option<String>,
    r1cs_path: Option<String>,
    wc_path: Option<String>,
}

#[derive(Args)]
struct ProveSeparationArgs {
    degrees: Option<String>,
    previous_username: Option<String>,
    username: Option<String>,
    proof_path: Option<String>,
    output_dir: Option<String>,
    public_params_path: Option<String>,
    r1cs_path: Option<String>,
    wc_path: Option<String>,
}

#[derive(Args)]
struct VerifyArgs {
    degrees: Option<String>,
    proof_path: Option<String>,
    public_params_path: Option<String>,
}

#[derive(Args)]
struct EcdsaArgs {
    key: Option<String>
}

/**
 * CLI for Grapevine
 */
pub fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Params(cmd) => {
            controllers::gen_params(cmd.r1cs.clone().unwrap(), cmd.output.clone().unwrap())
        }
        Commands::ProveSecret(cmd) => controllers::degree_0_proof(
            cmd.secret.clone().unwrap(),
            cmd.username.clone().unwrap(),
            cmd.output_dir.clone().unwrap(),
            cmd.public_params_path.clone().unwrap(),
            cmd.r1cs_path.clone().unwrap(),
            cmd.wc_path.clone().unwrap(),
        ),
        Commands::ProveSeparation(cmd) => {
            // parse degrees of separation
            let degrees = cmd.degrees.clone().unwrap().parse::<usize>().unwrap();
            // prove
            controllers::degree_n_proof(
                degrees,
                cmd.previous_username.clone().unwrap(),
                cmd.username.clone().unwrap(),
                cmd.proof_path.clone().unwrap(),
                cmd.output_dir.clone().unwrap(),
                cmd.public_params_path.clone().unwrap(),
                cmd.r1cs_path.clone().unwrap(),
                cmd.wc_path.clone().unwrap(),
            )
        }
        Commands::Verify(cmd) => {
            // parse degrees of separation
            let degrees = cmd.degrees.clone().unwrap().parse::<usize>().unwrap();
            // verify
            controllers::verify_proof(
                degrees,
                cmd.proof_path.clone().unwrap(),
                cmd.public_params_path.clone().unwrap(),
            );
        }
    }
}
