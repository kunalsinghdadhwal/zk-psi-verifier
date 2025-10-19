use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pasta_curves::Fp;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use zk_psi_verifier::{
    generate_proof, hash_string_to_field, hash_to_field, setup_eq, verify_proof, PsiCircuit,
};

#[derive(Parser)]
#[command(name = "zk-psi-cli")]
#[command(about = "ZK-PSI Prover and Verifier CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a zero-knowledge proof for private set intersection
    Prove {
        /// First set (comma-separated values, e.g., "1,2,3" or "alice,bob,carol")
        #[arg(short = 'a', long)]
        set_a: String,

        /// Second set (comma-separated values)
        #[arg(short = 'b', long)]
        set_b: String,

        /// Output file for the proof
        #[arg(short, long, default_value = "proof.bin")]
        output: PathBuf,

        /// Path to the proving key
        #[arg(long, default_value = "./keys/proving_key.bin")]
        pk: PathBuf,

        /// Path to the params file
        #[arg(long, default_value = "./keys/params.bin")]
        params: PathBuf,

        /// Output file for public inputs
        #[arg(long, default_value = "public_inputs.bin")]
        public_inputs_file: PathBuf,
    },

    /// Verify a zero-knowledge proof
    Verify {
        /// Path to the proof file
        #[arg(short, long)]
        proof: PathBuf,

        /// Path to public inputs file
        #[arg(long)]
        public_inputs: PathBuf,

        /// Path to the verifying key
        #[arg(long, default_value = "./keys/verifying_key.bin")]
        vk: PathBuf,

        /// Path to the params file
        #[arg(long, default_value = "./keys/params.bin")]
        params: PathBuf,
    },
}

/// Parse a comma-separated string into field elements
fn parse_set(input: &str) -> Result<Vec<Fp>> {
    input
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            // Try to parse as number first, otherwise hash as string
            if let Ok(num) = s.parse::<u64>() {
                Ok(hash_to_field(num))
            } else {
                Ok(hash_string_to_field(s))
            }
        })
        .collect()
}

fn prove_command(
    set_a_str: String,
    set_b_str: String,
    output: PathBuf,
    _pk_path: PathBuf,
    params_path: PathBuf,
    public_inputs_file: PathBuf,
) -> Result<()> {
    println!("ZK-PSI Proof Generation");

    // Parse input sets
    let start = Instant::now();
    let set_a = parse_set(&set_a_str).context("Failed to parse set A")?;
    let set_b = parse_set(&set_b_str).context("Failed to parse set B")?;

    println!("  Set A: {} elements", set_a.len());
    println!("  Set B: {} elements", set_b.len());

    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    println!("Intersection size: {}", intersection_size);

    // Create circuit with correct intersection size
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);

    let k_bytes = fs::read(&params_path)
        .with_context(|| format!("Failed to read params from {:?}", params_path))?;
    let k: u32 = bincode::deserialize(&k_bytes)?;

    println!("Params loaded (k={})", k);
    println!("Regenerating proving key...");

    let (params, pk, _vk) =
        setup_eq(k).map_err(|e| anyhow::anyhow!("Failed to setup keys: {:?}", e))?;

    println!("\nGenerating proof...");
    let proof_start = Instant::now();

    let public_inputs = vec![Fp::from(intersection_size)];
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;

    let proof_time = proof_start.elapsed();
    println!("Proof generated in {:.2?}", proof_time);
    println!("Proof size: {} bytes", proof.len());

    fs::write(&output, &proof).with_context(|| format!("Failed to write proof to {:?}", output))?;
    println!("Proof saved to {:?}", output);

    // Save public inputs (convert Fp to bytes manually)
    let public_inputs_bytes: Vec<u8> = intersection_size.to_le_bytes().to_vec();
    fs::write(&public_inputs_file, &public_inputs_bytes)
        .with_context(|| format!("Failed to write public inputs to {:?}", public_inputs_file))?;
    println!("Public inputs saved to {:?}", public_inputs_file);

    let total_time = start.elapsed();
    println!("Total time: {:.2?}", total_time);
    println!("Proof generation time: {:.2?}", proof_time);
    println!("Public intersection size: {}", intersection_size);
    println!("Proof Generated Successfully!");

    Ok(())
}

fn verify_command(
    proof_path: PathBuf,
    public_inputs_path: PathBuf,
    _vk_path: PathBuf,
    params_path: PathBuf,
) -> Result<()> {
    println!("ZK-PSI Proof Verification");

    let start = Instant::now();

    let proof = fs::read(&proof_path)
        .with_context(|| format!("Failed to read proof from {:?}", proof_path))?;
    println!("Proof loaded ({} bytes)", proof.len());

    let public_inputs_bytes = fs::read(&public_inputs_path)
        .with_context(|| format!("Failed to read public inputs from {:?}", public_inputs_path))?;

    // Parse intersection size from bytes
    let intersection_size = u64::from_le_bytes(
        public_inputs_bytes[..8]
            .try_into()
            .context("Invalid public inputs format")?,
    );

    let public_inputs = vec![Fp::from(intersection_size)];

    // Load params and regenerate verifying key
    let k_bytes = fs::read(&params_path)
        .with_context(|| format!("Failed to read params from {:?}", params_path))?;
    let k: u32 = bincode::deserialize(&k_bytes)?;

    println!("Params loaded (k={})", k);
    println!("Regenerating verifying key...");

    let (params, _pk, vk) =
        setup_eq(k).map_err(|e| anyhow::anyhow!("Failed to setup keys: {:?}", e))?;

    println!("\nVerifying proof...");
    let verify_start = Instant::now();

    match verify_proof(&params, &vk, &proof, &public_inputs) {
        Ok(_) => {
            let verify_time = verify_start.elapsed();
            println!("Verification completed in {:.2?}", verify_time);

            let total_time = start.elapsed();
            println!("Valid proof!");
            println!(
                "The prover knows two sets with intersection size: {}",
                intersection_size
            );
            println!("Total verification time: {:.2?}", total_time);
            Ok(())
        }
        Err(e) => {
            println!("Invalid proof!");
            Err(anyhow::anyhow!("Verification failed: {:?}", e))
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Prove {
            set_a,
            set_b,
            output,
            pk,
            params,
            public_inputs_file,
        } => prove_command(set_a, set_b, output, pk, params, public_inputs_file),

        Commands::Verify {
            proof,
            public_inputs,
            vk,
            params,
        } => verify_command(proof, public_inputs, vk, params),
    }
}
