use clap::{Parser, Subcommand};

use core::node_id_from_pubkey;
use crypto::Identity;

#[derive(Parser)]
#[command(name = "cli")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run,
    Keygen,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run => println!("starting"),
        Commands::Keygen => {
            let identity = Identity::new();
            let node_id = node_id_from_pubkey(&identity.verifying_key().to_bytes());
            println!("{}", node_id);
        }
    }
}
