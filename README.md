# ZK-PSI Verifier

A high-performance, production-ready Rust library for zero-knowledge Private Set Intersection (PSI) using Halo2 Plonk proofs. Built for zkVerify and decentralized ZK verification networks.

## Overview

**zk-psi-verifier** enables two parties to prove the size of their set intersection without revealing the sets themselves. Using cutting-edge zero-knowledge cryptography (Halo2 with KZG polynomial commitments), this library provides:

- **Zero-Knowledge**: Proofs reveal only the intersection count, nothing about the sets
- **Soundness**: Invalid proofs are rejected with overwhelming probability
- **Succinctness**: Compact proofs (~few KB) regardless of set sizes
- **Efficiency**: Optimized for zkVerify's universal verification infrastructure

## Why ZK-PSI?

Private Set Intersection has critical applications in:
- **Privacy-preserving contact discovery** (messaging apps)
- **Secure supply chain verification** (matching orders without revealing inventories)
- **Anonymous credential matching** (proving shared attributes without disclosure)
- **Regulatory compliance** (demonstrating data overlap without data sharing)

Traditional PSI requires interaction or reveals partial information. Our ZK-PSI generates **non-interactive, publicly verifiable proofs** suitable for blockchain and decentralized systems like zkVerify.

## Features

- Halo2 Plonk-based ZK circuit with KZG commitments
- Supports sets up to 32 elements (configurable with circuit parameter k)
- Blake3-based deterministic hashing to field elements
- Efficient equality gates and running sum accumulators
- Full CLI for proof generation and verification
- Comprehensive test suite with edge cases
- Criterion benchmarks for performance profiling
- Serialization/deserialization of keys and proofs (bincode)

## Installation

### Prerequisites

- Rust 1.70+ (install via rustup)
- Cargo

### Build from Source

```bash
git clone https://github.com/kunalsinghdadhwal/zk-psi-verifier.git
cd zk-psi-verifier
cargo build --release
```

## Quick Start

### 1. Generate Cryptographic Keys

```bash
cargo run --release --bin zk-psi-setup -- --k 12 --output-dir ./keys
```

This generates:
- params.bin: Universal setup parameters (2^12 = 4096 rows)
- proving_key.bin: For proof generation
- verifying_key.bin: For proof verification

### 2. Generate a Proof

```bash
cargo run --release --bin zk-psi-cli -- prove \
  --set-a "1,2,3,4,5" \
  --set-b "3,4,5,6,7" \
  --output proof.bin \
  --pk ./keys/proving_key.bin \
  --params ./keys/params.bin \
  --public-inputs-file public_inputs.bin
```

### 3. Verify the Proof

```bash
cargo run --release --bin zk-psi-cli -- verify \
  --proof proof.bin \
  --public-inputs public_inputs.bin \
  --vk ./keys/verifying_key.bin \
  --params ./keys/params.bin
```

### Using String Values

The CLI automatically hashes non-numeric inputs:

```bash
cargo run --release --bin zk-psi-cli -- prove \
  --set-a "alice,bob,charlie" \
  --set-b "bob,charlie,david" \
  --output proof.bin \
  --pk ./keys/proving_key.bin \
  --params ./keys/params.bin
```

## Library Usage

### Example Code

```rust
use pasta_curves::Fp;
use zk_psi_verifier::{hash_to_field, PsiCircuit, setup, generate_proof, verify_proof};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Hash input sets to field elements
    let set_a: Vec<Fp> = vec![1, 2, 3].iter().map(|&x| hash_to_field(x)).collect();
    let set_b: Vec<Fp> = vec![2, 3, 4].iter().map(|&x| hash_to_field(x)).collect();
    
    // Compute intersection size (for witness)
    let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
    let intersection_size = circuit.compute_intersection_size();
    
    // Trusted setup
    let k = 10;
    let (params, pk, vk) = setup(k)?;
    
    // Generate proof
    let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
    let public_inputs = vec![Fp::from(intersection_size)];
    let proof = generate_proof(&params, &pk, circuit, &public_inputs)
        .map_err(|e| format!("Proof failed: {:?}", e))?;
    
    // Verify proof
    verify_proof(&params, &vk, &proof, &public_inputs)
        .map_err(|e| format!("Verification failed: {:?}", e))?;
    
    println!("Proved intersection size: {}", intersection_size);
    Ok(())
}
```

See examples/ for more usage patterns.

## Architecture

### Circuit Design

The PSI circuit uses a comparison matrix approach:

1. Input: Two sets A and B (hashed to field elements)
2. Witness: For each pair (a_i, b_j), compute match_bit = 1 if a_i == b_j, else 0
3. Constraints:
   - Boolean gate: match_bit * (match_bit - 1) == 0
   - Equality gate: (a_i - b_j) * (1 - match_bit) == 0
   - Sum gate: sum[i] = sum[i-1] + match_bit[i]
4. Public input: Final sum (intersection size)

### Security Properties

- **Zero-Knowledge**: Proof reveals only the intersection count via polynomial commitments
- **Soundness**: Fiat-Shamir transform ensures non-interactive security
- **Succinctness**: Proof size ~O(log n) due to KZG logarithmic verification

### Performance Characteristics

| Set Size (n×n) | Proof Gen | Verification | Proof Size |
|----------------|-----------|--------------|------------|
| 4×4            | ~335ms    | ~13.7ms      | ~3KB       |
| 8×8            | ~346ms    | ~13.2ms      | ~3KB       |
| 16×16          | ~360ms    | ~12.8ms      | ~3KB       |

## Testing

Run the full test suite:

```bash
cargo test
```

Tests include:
- Hash function determinism
- Intersection computation correctness
- Circuit synthesis validity
- Full prove/verify flow
- Edge cases (empty sets, full overlap, mismatched sizes)
- Invalid proof rejection

## Benchmarking

Generate performance reports:

```bash
cargo bench
```

Criterion outputs HTML reports to target/criterion/

## Roadmap & Extensions

**Problem**: Proving multiple PSI instances (e.g., 10 pairs of sets) requires 10 separate proofs.

**Solution**: Use proof recursion to aggregate multiple PSI proofs into one:

1. Generate N individual PSI proofs (P₁, P₂, ..., Pₙ)
2. Create a recursive circuit that verifies all N proofs inside a single Halo2 circuit
3. Output one master proof attesting to all N intersections

**Benefits**:
- Constant verification time regardless of batch size
- Reduced on-chain costs (1 verification vs. N)
- Enables privacy-preserving analytics (prove aggregate statistics)

**Implementation**:
- Use Halo2 IPA or KZG recursion
- Modify PsiCircuit to accept a vector of sub-proofs
- Add aggregation logic in lib.rs

## Acknowledgments

Built with:
- Halo2 by Zcash/Electric Coin Company
- pasta_curves (Pallas/Vesta curves)
- Inspired by research on private set intersection and zkSNARKs