use anyhow::Result;
use std::fs;
use std::path::PathBuf;
use clap::Parser;
use zk_psi_verifier::setup;

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
    
    println!("Generating setup with k={} (2^{} = {} rows)", args.k, args.k, 1u64 << args.k);
    
    // Create output directory if it doesn't exist
    fs::create_dir_all(&args.output_dir)?;
    
    // Generate keys
    let (params, pk, vk) = setup(args.k)
        .map_err(|e| anyhow::anyhow!("Failed to generate keys: {:?}", e))?;
    
    println!("✓ Keys generated successfully");
    
    // Serialize and save params
    let params_path = args.output_dir.join("params.bin");
    let params_bytes = bincode::serialize(&params.k())?;
    fs::write(&params_path, params_bytes)?;
    println!("✓ Saved params to {:?}", params_path);
    
    // Serialize and save proving key
    let pk_path = args.output_dir.join("proving_key.bin");
    let pk_bytes = bincode::serialize(&pk)?;
    fs::write(&pk_path, pk_bytes)?;
    println!("✓ Saved proving key to {:?} ({} bytes)", pk_path, pk_bytes.len());
    
    // Serialize and save verifying key
    let vk_path = args.output_dir.join("verifying_key.bin");
    let vk_bytes = bincode::serialize(&vk)?;
    fs::write(&vk_path, vk_bytes)?;
    println!("✓ Saved verifying key to {:?} ({} bytes)", vk_path, vk_bytes.len());
    
    println!("\n✅ Setup complete! Keys saved to {:?}", args.output_dir);
    println!("\nNext steps:");
    println!("  1. Use 'cli prove' to generate proofs");
    println!("  2. Use 'cli verify' to verify proofs");
    
    Ok(())
}
