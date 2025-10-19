use pasta_curves::Fp;
use zk_psi_verifier::{hash_string_to_field, PsiCircuit, setup, generate_proof, verify_proof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ZK-PSI String Sets Example ===\n");
    
    // Alice's contacts
    let alice_contacts = vec!["alice@example.com", "bob@example.com", "charlie@example.com"];
    
    // Bob's contacts
    let bob_contacts = vec!["bob@example.com", "charlie@example.com", "david@example.com"];
    
    println!("Alice's contacts: {:?}", alice_contacts);
    println!("Bob's contacts: {:?}", bob_contacts);
    
    // Hash strings to field elements
    let set_a: Vec<Fp> = alice_contacts.iter().map(|&s| hash_string_to_field(s)).collect();
    let set_b: Vec<Fp> = bob_contacts.iter().map(|&s| hash_string_to_field(s)).collect();
    
    // Compute intersection
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    
    println!("\nCommon contacts: {}", intersection_size);
    println!("(bob@example.com and charlie@example.com)\n");
    
    // Setup
    println!("Performing trusted setup...");
    let k = 10;
    let (params, pk, vk) = setup(k)?;
    println!("✓ Setup complete\n");
    
    // Alice generates a proof
    println!("Alice generating proof of common contacts...");
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .map_err(|e| format!("Proof generation failed: {:?}", e))?;
    
    println!("✓ Alice's proof generated\n");
    
    // Bob verifies the proof
    println!("Bob verifying the proof...");
    verify_proof(&params, &vk, &proof, &public_inputs)
        .map_err(|e| format!("Verification failed: {:?}", e))?;
    
    println!("✓ Bob confirmed: {} common contacts exist\n", intersection_size);
    
    println!("=== Summary ===");
    println!("Alice and Bob discovered they have {} common contacts", intersection_size);
    println!("without revealing their full contact lists to each other!");
    
    Ok(())
}
