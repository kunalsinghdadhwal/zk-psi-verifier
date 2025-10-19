use zk_psi_verifier::{hash_to_field, PsiCircuit, setup_eq, generate_proof, verify_proof};
use pasta_curves::Fp;
use pasta_curves::EqAffine;

#[test]
fn test_serialization_deserialization() {
    let k = 10;
    let (params, pk, vk) = setup_eq(k).unwrap();
    
    // Serialize
    let pk_bytes = bincode::serialize(&pk).unwrap();
    let vk_bytes = bincode::serialize(&vk).unwrap();
    
    // Deserialize
    let pk_recovered: halo2_proofs::plonk::ProvingKey<EqAffine> = 
        bincode::deserialize(&pk_bytes).unwrap();
    let vk_recovered: halo2_proofs::plonk::VerifyingKey<EqAffine> = 
        bincode::deserialize(&vk_bytes).unwrap();
    
    // Use recovered keys
    let set_a = vec![hash_to_field(1), hash_to_field(2)];
    let set_b = vec![hash_to_field(2), hash_to_field(3)];
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 1);
    let public_inputs = vec![Fp::from(1u64)];
    
    let proof = generate_proof(&params, &pk_recovered, circuit, &public_inputs).unwrap();
    verify_proof(&params, &vk_recovered, &proof, &public_inputs).unwrap();
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
