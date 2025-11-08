use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use hex;
use std::convert::TryInto;
use std::path::PathBuf;
use x_wing::{
    Encapsulate, Decapsulate, generate_key_pair_from_os_rng,
    EncapsulationKey, DecapsulationKey, Ciphertext,
    ENCAPSULATION_KEY_SIZE, DECAPSULATION_KEY_SIZE, CIPHERTEXT_SIZE,
};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    GenKey {
        /// Output encapsulation (public) key
        #[arg(long)]
        pub_out: PathBuf,
        /// Output decapsulation (private) key
        #[arg(long)]
        priv_out: PathBuf,
    },

    /// Encapsulate a shared secret for a peer public key
    Encapsulate {
        /// Peer public key file
        #[arg(long)]
        peer: PathBuf,
        /// Output ciphertext file
        #[arg(long)]
        out: PathBuf,
    },

    /// Decapsulate a shared secret using a private key and ciphertext
    Decapsulate {
        /// Private key file
        #[arg(long, name = "priv")]
        priv_key: PathBuf,
        /// Ciphertext file
        #[arg(long)]
        cipher: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKey { pub_out, priv_out } => {
            let (ek, dk) = generate_key_pair_from_os_rng();

            std::fs::write(pub_out, ek.as_bytes())?;
            std::fs::write(priv_out, dk.to_bytes())?;

            println!("✅ Keypair generated.");
        }

        Commands::Encapsulate { peer, out } => {
            let pk_bytes = std::fs::read(peer)?;
            let pk_array: [u8; ENCAPSULATION_KEY_SIZE] = pk_bytes.try_into().map_err(|_| anyhow!("Invalid key length"))?;
            let peer_pk = EncapsulationKey::from(&pk_array);

            // Encapsulate using the peer's public key
            // We need to use the correct RNG - let's use the x-wing crate's internal RNG
            use rand_core::OsRng as XWingOsRng;
            let (ct, ss) = peer_pk.encapsulate(&mut XWingOsRng)?;
            std::fs::write(out, ct.to_bytes())?;
            // Output shared secret in hex to stdout (as expected by Python scripts)
            println!("{}", hex::encode(ss));
        }

        Commands::Decapsulate { priv_key, cipher } => {
            let sk_bytes = std::fs::read(priv_key)?;
            let sk_array: [u8; DECAPSULATION_KEY_SIZE] = sk_bytes.try_into().map_err(|_| anyhow!("Invalid key length"))?;
            let dk = DecapsulationKey::from(sk_array);

            let ct_bytes = std::fs::read(cipher)?;
            let ct_array: [u8; CIPHERTEXT_SIZE] = ct_bytes.try_into().map_err(|_| anyhow!("Invalid ct length"))?;
            let ct = Ciphertext::from(&ct_array);

            let ss = dk.decapsulate(&ct)?;
            // Output shared secret in hex to stdout (as expected by Python scripts)
            println!("{}", hex::encode(ss));
        }
    }

    Ok(())
}
