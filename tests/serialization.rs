use pasta_curves::Fp;
use zk_psi_verifier::{generate_proof, hash_to_field, setup_eq, verify_proof, PsiCircuit};

#[test]
fn test_key_regeneration() {
    // Test that we can regenerate keys with the same k value
    let k = 10;
    let (params1, pk1, vk1) = setup_eq(k).unwrap();
    let (params2, pk2, vk2) = setup_eq(k).unwrap();

    // Use first set of keys
    let set_a = vec![hash_to_field(1), hash_to_field(2)];
    let set_b = vec![hash_to_field(2), hash_to_field(3)];
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 1);
    let public_inputs = vec![Fp::from(1u64)];

    let proof1 = generate_proof(&params1, &pk1, circuit.clone(), &public_inputs).unwrap();
    verify_proof(&params1, &vk1, &proof1, &public_inputs).unwrap();

    // Verify with second set of keys (should work since same k)
    verify_proof(&params2, &vk2, &proof1, &public_inputs).unwrap();

    // Generate proof with second keys
    let proof2 = generate_proof(&params2, &pk2, circuit, &public_inputs).unwrap();
    verify_proof(&params1, &vk1, &proof2, &public_inputs).unwrap();
}

#[test]
fn test_proof_portability() {
    let k = 10;
    let (params, pk, vk) = setup_eq(k).unwrap();

    let set_a = vec![hash_to_field(10), hash_to_field(20), hash_to_field(30)];
    let set_b = vec![hash_to_field(20), hash_to_field(30), hash_to_field(40)];

    let circuit = PsiCircuit::new(set_a, set_b, 2);
    let public_inputs = vec![Fp::from(2u64)];

    // Generate proof
    let proof = generate_proof(&params, &pk, circuit, &public_inputs).unwrap();

    // Serialize and deserialize proof
    let proof_copy = proof.clone();

    // Verify both
    verify_proof(&params, &vk, &proof, &public_inputs).unwrap();
    verify_proof(&params, &vk, &proof_copy, &public_inputs).unwrap();
}
