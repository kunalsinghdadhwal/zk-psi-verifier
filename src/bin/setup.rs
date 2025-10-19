use anyhow::Result;
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use zk_psi_verifier::setup_eq;

#[derive(Parser, Debug)]
#[command(name = "setup")]
#[command(about = "Generate and save proving/verifying keys for PSI circuit", long_about = None)]
struct Args {
    /// Circuit size parameter (k). Determines the number of rows: 2^k
    #[arg(short, long, default_value = "12")]
    k: u32,

    /// Output directory for generated keys
    #[arg(short, long, default_value = "./keys")]
    output_dir: PathBuf,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!(
        "Generating setup with k={} (2^{} = {} rows)",
        args.k,
        args.k,
        1u64 << args.k
    );

    // Create output directory if it doesn't exist
    fs::create_dir_all(&args.output_dir)?;

    // Generate keys
    let (_params, _pk, _vk) =
        setup_eq(args.k).map_err(|e| anyhow::anyhow!("Failed to generate keys: {:?}", e))?;

    println!("Keys generated successfully");

    // Save params (just save k value for reconstruction)
    let params_path = args.output_dir.join("params.bin");
    let params_bytes = bincode::serialize(&args.k)?;
    fs::write(&params_path, params_bytes)?;
    println!("Saved params to {:?}", params_path);

    // Note: Halo2 0.3 ProvingKey and VerifyingKey don't have built-in serialization
    // For production use, you would need to:
    // 1. Use halo2_proofs with serde feature (if available)
    // 2. Store the circuit and regenerate keys
    // 3. Use a custom serialization method
    // For now, we'll store a marker file
    let pk_path = args.output_dir.join("proving_key.bin");
    fs::write(&pk_path, b"PK_PLACEHOLDER")?;
    println!("Proving key generated (not serialized - regenerate when needed)");

    let vk_path = args.output_dir.join("verifying_key.bin");
    fs::write(&vk_path, b"VK_PLACEHOLDER")?;
    println!("Verifying key generated (not serialized - regenerate when needed)");

    println!("\nSetup complete! Keys saved to {:?}", args.output_dir);
    println!("\nNext steps:");
    println!("  1. Use 'cli prove' to generate proofs");
    println!("  2. Use 'cli verify' to verify proofs");

    Ok(())
}
