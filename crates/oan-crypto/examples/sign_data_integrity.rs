use std::{env, fs};

use oan_crypto::sign_oan_data_integrity;
use serde_json::Value;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let document_path = args.next().ok_or("missing document path")?;
    let private_key_path = args.next().ok_or("missing private key path")?;
    let did = args.next().ok_or("missing did")?;
    let document: Value = serde_json::from_str(&fs::read_to_string(document_path)?)?;
    let private_key_jwk: Value = serde_json::from_str(&fs::read_to_string(private_key_path)?)?;
    let signed = sign_oan_data_integrity(document, &did, private_key_jwk).await?;
    println!("{}", serde_json::to_string(&signed)?);
    Ok(())
}
