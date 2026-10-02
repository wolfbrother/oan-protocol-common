use std::{env, fs};

use oan_crypto::verify_did_document_proof_standard_value_blocking;
use serde_json::Value;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let document_path = env::args().nth(1).ok_or("missing DID document path")?;
    let document: Value = serde_json::from_str(&fs::read_to_string(document_path)?)?;
    verify_did_document_proof_standard_value_blocking(document)?;
    Ok(())
}
