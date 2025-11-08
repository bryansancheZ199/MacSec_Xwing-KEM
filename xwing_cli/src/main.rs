use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::Write;
use x_wing::{Encapsulate, Decapsulate, GenerateKeypair};
use hex::encode;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenKey { priv_out: String, pub_out: String },
    Encaps { peer_pub: String, out: String },
    Decaps { cipher: String, priv_key: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { priv_out, pub_out } => {
            let (pk, sk) = x_wing::GenerateKeypair::generate()?;
            std::fs::write(&priv_out, sk)?;
            std::fs::write(&pub_out, pk)?;
            println!("OK");
        }
        Commands::Encaps { peer_pub, out } => {
            let pk = std::fs::read(peer_pub)?;
            let (ct, ss) = x_wing::Encapsulate::encapsulate(&pk)?;
            std::fs::write(&out, ct)?;
            // for debugging: print shared secret as hex
            println!("{}", encode(ss));
        }
        Commands::Decaps { cipher, priv_key } => {
            let ct = std::fs::read(cipher)?;
            let sk = std::fs::read(priv_key)?;
            let ss = x_wing::Decapsulate::decapsulate(&ct, &sk)?;
            println!("{}", encode(ss)); // prints shared secret hex to stdout
        }
    }
    Ok(())
}
