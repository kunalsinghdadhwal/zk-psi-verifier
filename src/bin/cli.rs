use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pasta_curves::Fp;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use ff::PrimeField;
use pasta_curves::EqAffine;
use halo2_proofs::plonk::{ProvingKey, VerifyingKey};

use zk_psi_verifier::{
    hash_to_field, hash_string_to_field, PsiCircuit, generate_proof, verify_proof,
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
    pk_path: PathBuf,
    params_path: PathBuf,
    public_inputs_file: PathBuf,
) -> Result<()> {
    println!("🔐 ZK-PSI Proof Generation");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Parse input sets
    let start = Instant::now();
    let set_a = parse_set(&set_a_str).context("Failed to parse set A")?;
    let set_b = parse_set(&set_b_str).context("Failed to parse set B")?;
    
    println!("📊 Input Sets:");
    println!("  Set A: {} elements", set_a.len());
    println!("  Set B: {} elements", set_b.len());
    
    // Compute actual intersection
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    println!("  Intersection size: {}", intersection_size);
    
    // Create circuit with correct intersection size
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    
    // Load params
    println!("\n📂 Loading cryptographic parameters...");
    let k_bytes = fs::read(&params_path)
        .with_context(|| format!("Failed to read params from {:?}", params_path))?;
    let k: u32 = bincode::deserialize(&k_bytes)?;
    let params = halo2_proofs::poly::commitment::Params::<EqAffine>::new(k);
    println!("  ✓ Params loaded (k={})", k);
    
    // Load proving key
    let pk_bytes = fs::read(&pk_path)
        .with_context(|| format!("Failed to read proving key from {:?}", pk_path))?;
    let pk: ProvingKey<EqAffine> = bincode::deserialize(&pk_bytes)?;
    println!("  ✓ Proving key loaded ({} bytes)", pk_bytes.len());
    
    // Generate proof
    println!("\n⚙️  Generating proof...");
    let proof_start = Instant::now();
    
    let public_inputs = vec![Fp::from(intersection_size)];
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .map_err(|e| anyhow::anyhow!("Proof generation failed: {:?}", e))?;
    
    let proof_time = proof_start.elapsed();
    println!("  ✓ Proof generated in {:.2?}", proof_time);
    println!("  Proof size: {} bytes", proof.len());
    
    // Save proof
    fs::write(&output, &proof)
        .with_context(|| format!("Failed to write proof to {:?}", output))?;
    println!("  ✓ Proof saved to {:?}", output);
    
    // Save public inputs
    let public_inputs_bytes = bincode::serialize(&public_inputs)?;
    fs::write(&public_inputs_file, &public_inputs_bytes)
        .with_context(|| format!("Failed to write public inputs to {:?}", public_inputs_file))?;
    println!("  ✓ Public inputs saved to {:?}", public_inputs_file);
    
    let total_time = start.elapsed();
    println!("\n✅ Success!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Total time: {:.2?}", total_time);
    println!("Proof generation time: {:.2?}", proof_time);
    println!("Public intersection size: {}", intersection_size);
    
    Ok(())
}

fn verify_command(
    proof_path: PathBuf,
    public_inputs_path: PathBuf,
    vk_path: PathBuf,
    params_path: PathBuf,
) -> Result<()> {
    println!("✓ ZK-PSI Proof Verification");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    let start = Instant::now();
    
    // Load proof
    println!("📂 Loading proof and keys...");
    let proof = fs::read(&proof_path)
        .with_context(|| format!("Failed to read proof from {:?}", proof_path))?;
    println!("  ✓ Proof loaded ({} bytes)", proof.len());
    
    // Load public inputs
    let public_inputs_bytes = fs::read(&public_inputs_path)
        .with_context(|| format!("Failed to read public inputs from {:?}", public_inputs_path))?;
    let public_inputs: Vec<Fp> = bincode::deserialize(&public_inputs_bytes)?;
    
    // Extract intersection size from public inputs
    let intersection_size = public_inputs[0].get_lower_128() as u64;
    println!("  ✓ Public intersection size: {}", intersection_size);
    
    // Load params
    let k_bytes = fs::read(&params_path)
        .with_context(|| format!("Failed to read params from {:?}", params_path))?;
    let k: u32 = bincode::deserialize(&k_bytes)?;
    let params = halo2_proofs::poly::commitment::Params::<EqAffine>::new(k);
    println!("  ✓ Params loaded (k={})", k);
    
    // Load verifying key
    let vk_bytes = fs::read(&vk_path)
        .with_context(|| format!("Failed to read verifying key from {:?}", vk_path))?;
    let vk: VerifyingKey<EqAffine> = bincode::deserialize(&vk_bytes)?;
    println!("  ✓ Verifying key loaded ({} bytes)", vk_bytes.len());
    
    // Verify proof
    println!("\n🔍 Verifying proof...");
    let verify_start = Instant::now();
    
    match verify_proof(&params, &vk, &proof, &public_inputs) {
        Ok(_) => {
            let verify_time = verify_start.elapsed();
            println!("  ✓ Verification completed in {:.2?}", verify_time);
            
            let total_time = start.elapsed();
            println!("\n✅ PROOF VALID!");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("The prover knows two sets with intersection size: {}", intersection_size);
            println!("Total verification time: {:.2?}", total_time);
            Ok(())
        }
        Err(e) => {
            println!("\n❌ PROOF INVALID!");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━");
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
