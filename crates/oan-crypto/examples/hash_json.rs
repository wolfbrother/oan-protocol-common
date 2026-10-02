use std::{env, fs};

use oan_core::CryptoSuite;
use oan_crypto::hash_json_with_suite;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("missing json path")?;
    let value: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    println!(
        "sha256:{}",
        hash_json_with_suite(CryptoSuite::Ed25519Sha256, &value)?
    );
    Ok(())
}
