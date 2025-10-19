use ff::PrimeField;
use pasta_curves::Fp;
use zk_psi_verifier::{
    hash_to_field, PsiCircuit, setup, generate_proof, verify_proof,
};

#[test]
fn test_full_proof_verification_flow() {
    // Create two sets with known intersection
    let set_a = vec![
        hash_to_field(1),
        hash_to_field(2),
        hash_to_field(3),
        hash_to_field(4),
    ];
    
    let set_b = vec![
        hash_to_field(2),
        hash_to_field(3),
        hash_to_field(5),
        hash_to_field(6),
    ];
    
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    assert_eq!(intersection_size, 2, "Intersection should be {2, 3}");
    
    // Setup
    let k = 10;
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    // Create circuit with correct intersection size
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    
    // Generate proof
    let public_inputs = vec![Fp::from(intersection_size)];
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .expect("Proof generation failed");
    
    assert!(!proof.is_empty(), "Proof should not be empty");
    
    // Verify proof
    verify_proof(&params, &vk, &proof, &public_inputs)
        .expect("Proof verification failed");
}

#[test]
fn test_empty_intersection() {
    let set_a = vec![hash_to_field(1), hash_to_field(2)];
    let set_b = vec![hash_to_field(3), hash_to_field(4)];
    
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    assert_eq!(intersection_size, 0);
    
    let k = 10;
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .expect("Proof generation failed");
    
    verify_proof(&params, &vk, &proof, &public_inputs)
        .expect("Proof verification failed");
}

#[test]
fn test_full_intersection() {
    let set_a = vec![
        hash_to_field(1),
        hash_to_field(2),
        hash_to_field(3),
    ];
    let set_b = set_a.clone();
    
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    assert_eq!(intersection_size, 3);
    
    let k = 10;
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .expect("Proof generation failed");
    
    verify_proof(&params, &vk, &proof, &public_inputs)
        .expect("Proof verification failed");
}

#[test]
fn test_invalid_proof_fails() {
    let set_a = vec![hash_to_field(1), hash_to_field(2)];
    let set_b = vec![hash_to_field(2), hash_to_field(3)];
    
    // Actual intersection is 1, but we claim it's 0
    let claimed_intersection = 0u64;
    
    let k = 10;
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    let circuit = PsiCircuit::new(set_a, set_b, claimed_intersection);
    let public_inputs = vec![Fp::from(claimed_intersection)];
    
    // This should fail during proof generation or create an invalid proof
    let proof_result = generate_proof(&params, &pk, circuit, &public_inputs);
    
    // If proof generation succeeds, verification should fail
    if let Ok(proof) = proof_result {
        let verify_result = verify_proof(&params, &vk, &proof, &public_inputs);
        assert!(verify_result.is_err(), "Invalid proof should not verify");
    }
}

#[test]
fn test_large_sets() {
    // Test with larger sets (16 elements each)
    let set_a: Vec<Fp> = (1..=16).map(hash_to_field).collect();
    let set_b: Vec<Fp> = (10..=25).map(hash_to_field).collect();
    
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    assert_eq!(intersection_size, 7, "Intersection should be {10..=16}");
    
    let k = 12; // Need more rows for larger sets
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .expect("Proof generation failed");
    
    verify_proof(&params, &vk, &proof, &public_inputs)
        .expect("Proof verification failed");
}

#[test]
fn test_single_element_sets() {
    let set_a = vec![hash_to_field(42)];
    let set_b = vec![hash_to_field(42)];
    
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    assert_eq!(intersection_size, 1);
    
    let k = 10;
    let (params, pk, vk) = setup(k).expect("Setup failed");
    
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .expect("Proof generation failed");
    
    verify_proof(&params, &vk, &proof, &public_inputs)
        .expect("Proof verification failed");
}
