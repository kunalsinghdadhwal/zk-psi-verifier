use pasta_curves::Fp;
use zk_psi_verifier::{hash_to_field, PsiCircuit, setup, generate_proof, verify_proof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZK-PSI Basic Example ===\n");
    
    // Define two sets
    let set_a_values = vec![1, 2, 3, 4, 5];
    let set_b_values = vec![3, 4, 5, 6, 7];
    
    println!("Set A: {:?}", set_a_values);
    println!("Set B: {:?}", set_b_values);
    
    // Hash the values to field elements
    let set_a: Vec<Fp> = set_a_values.iter().map(|&x| hash_to_field(x)).collect();
    let set_b: Vec<Fp> = set_b_values.iter().map(|&x| hash_to_field(x)).collect();
    
    // Create circuit to compute intersection
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    
    println!("\nIntersection size: {}", intersection_size);
    println!("(Elements {}, {}, {} are common)\n", 3, 4, 5);
    
    // Perform trusted setup
    println!("Performing trusted setup...");
    let k = 10; // Circuit size parameter
    let (params, pk, vk) = setup(k)?;
    println!("✓ Setup complete\n");
    
    // Generate proof
    println!("Generating zero-knowledge proof...");
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    
    println!("✓ Proof generated ({} bytes)\n", proof.len());
    
    // Verify proof
    println!("Verifying proof...");
    verify_proof(&params, &vk, &proof, &public_inputs)
        .map_err(|e| format!("Verification failed: {:?}", e))?;
    
    println!("✓ Proof verified successfully!\n");
    
    println!("=== Summary ===");
    println!("The prover has demonstrated knowledge of two sets");
    println!("with intersection size {} without revealing the sets!", intersection_size);
    
    Ok(())
}
