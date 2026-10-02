use std::{env, fs};

use oan_core::{CryptoSuite, DidDocument};
use oan_crypto::hash_json_with_suite;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("missing did document path")?;
    let document: DidDocument = serde_json::from_str(&fs::read_to_string(path)?)?;
    println!(
        "sha256:{}",
        hash_json_with_suite(CryptoSuite::Ed25519Sha256, &document)?
    );
    Ok(())
}
