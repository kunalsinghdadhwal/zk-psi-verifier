use ff::PrimeField;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, ProvingKey,
        Selector, VerifyingKey, create_proof, keygen_pk, keygen_vk,
        verify_proof as halo2_verify_proof,
    },
    poly::Rotation,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{EqAffine, Fp};
use rand::rngs::OsRng;

pub const MAX_SET_SIZE: usize = 32;

type Halo2Setup<E> = (
    halo2_proofs::poly::commitment::Params<E>,
    ProvingKey<E>,
    VerifyingKey<E>,
);

pub fn draw_circuit(k: u32, circuit: &PsiCircuit) {
    use plotters::prelude::*;

    let base = BitMapBackend::new("zk-psi-circuit-layout.png", (1600, 1600)).into_drawing_area();
    base.fill(&WHITE).unwrap();
    let base = base
        .titled("PSI Circuit Layout", ("sans-serif", 24))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .show_equality_constraints(true)
        .render(k, circuit, &base)
        .unwrap();
}

pub fn hash_to_field(value: u64) -> Fp {
    let bytes = value.to_le_bytes();
    let hash = blake3::hash(&bytes);
    let hash_bytes = hash.as_bytes();

    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&hash_bytes[..31]);

    Fp::from_repr(repr).unwrap()
}

/// Hash a string to a field element
pub fn hash_string_to_field(s: &str) -> Fp {
    let hash = blake3::hash(s.as_bytes());
    let hash_bytes = hash.as_bytes();

    let mut repr = [0u8; 32];
    repr[..31].copy_from_slice(&hash_bytes[..31]);

    Fp::from_repr(repr).unwrap()
}

#[derive(Debug, Clone)]
pub struct PsiConfig {
    /// Advice columns for set A elements
    set_a: Column<Advice>,
    /// Advice columns for set B elements
    set_b: Column<Advice>,
    /// Advice column for match bits (1 if elements match, 0 otherwise)
    match_bit: Column<Advice>,
    /// Advice column for running sum of matches
    sum: Column<Advice>,
    /// Selector for equality check gates
    q_equality: Selector,
    /// Selector for sum gates
    q_sum: Selector,
    /// Instance column for public intersection size
    instance: Column<Instance>,
}

impl PsiConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let set_a = meta.advice_column();
        let set_b = meta.advice_column();
        let match_bit = meta.advice_column();
        let sum = meta.advice_column();
        let instance = meta.instance_column();

        meta.enable_equality(set_a);
        meta.enable_equality(set_b);
        meta.enable_equality(match_bit);
        meta.enable_equality(sum);
        meta.enable_equality(instance);

        let q_equality = meta.selector();
        let q_sum = meta.selector();

        // Equality gate: Ensures match_bit is correct
        // If set_a[i] == set_b[j], then match_bit must be 1, else 0
        // Constraint: match_bit * (match_bit - 1) == 0 (boolean constraint)
        // Constraint: (set_a - set_b) * (1 - match_bit) == 0 (if equal, match_bit must be 1)
        meta.create_gate("equality check", |meta| {
            let q = meta.query_selector(q_equality);
            let a = meta.query_advice(set_a, Rotation::cur());
            let b = meta.query_advice(set_b, Rotation::cur());
            let match_bit = meta.query_advice(match_bit, Rotation::cur());

            vec![
                // match_bit is boolean
                q.clone()
                    * (match_bit.clone() * (match_bit.clone() - Expression::Constant(Fp::one()))),
                // if a == b, then match_bit must be 1
                q * (a - b) * (Expression::Constant(Fp::one()) - match_bit),
            ]
        });

        // Sum gate: Accumulates the match count
        // sum[i] = sum[i-1] + match_bit[i]
        meta.create_gate("sum accumulator", |meta| {
            let q = meta.query_selector(q_sum);
            let sum_prev = meta.query_advice(sum, Rotation::prev());
            let sum_cur = meta.query_advice(sum, Rotation::cur());
            let match_bit = meta.query_advice(match_bit, Rotation::cur());

            vec![q * (sum_cur - sum_prev - match_bit)]
        });

        Self {
            set_a,
            set_b,
            match_bit,
            sum,
            q_equality,
            q_sum,
            instance,
        }
    }

    /// Assign a single comparison and update running sum
    pub fn assign_comparison(
        &self,
        mut layouter: impl Layouter<Fp>,
        a_val: Fp,
        b_val: Fp,
        prev_sum: Option<AssignedCell<Fp, Fp>>,
        offset: usize,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || format!("comparison row {}", offset),
            |mut region| {
                self.q_equality.enable(&mut region, 0)?;
                if offset > 0 {
                    self.q_sum.enable(&mut region, 0)?;
                }

                region.assign_advice(|| "set_a", self.set_a, 0, || Value::known(a_val))?;

                region.assign_advice(|| "set_b", self.set_b, 0, || Value::known(b_val))?;

                let is_equal = a_val == b_val;
                let match_bit_val = if is_equal { Fp::one() } else { Fp::zero() };

                region.assign_advice(
                    || "match_bit",
                    self.match_bit,
                    0,
                    || Value::known(match_bit_val),
                )?;

                let new_sum = if let Some(ref prev) = prev_sum {
                    prev.value().copied() + Value::known(match_bit_val)
                } else {
                    Value::known(match_bit_val)
                };

                let sum_cell = region.assign_advice(|| "sum", self.sum, 0, || new_sum)?;

                Ok(sum_cell)
            },
        )
    }
}

/// PSI Circuit structure
#[derive(Debug, Clone, Default)]
pub struct PsiCircuit {
    /// First set of hashed elements
    pub set_a: Vec<Fp>,
    /// Second set of hashed elements
    pub set_b: Vec<Fp>,
    /// Expected intersection size (public input)
    pub intersection_size: u64,
}

impl PsiCircuit {
    /// Create a new PSI circuit with two sets
    pub fn new(set_a: Vec<Fp>, set_b: Vec<Fp>, intersection_size: u64) -> Self {
        assert!(set_a.len() <= MAX_SET_SIZE, "Set A exceeds maximum size");
        assert!(set_b.len() <= MAX_SET_SIZE, "Set B exceeds maximum size");

        Self {
            set_a,
            set_b,
            intersection_size,
        }
    }

    /// Compute the actual intersection size (for witness generation)
    pub fn compute_intersection_size(&self) -> u64 {
        let mut count = 0u64;
        for a in &self.set_a {
            for b in &self.set_b {
                if a == b {
                    count += 1;
                    break; // Count each element in A only once
                }
            }
        }
        count
    }
}

impl Circuit<Fp> for PsiCircuit {
    type Config = PsiConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        PsiConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let mut sum_cell: Option<AssignedCell<Fp, Fp>> = None;
        let mut row = 0;

        // Compare each element in set_a with each element in set_b
        for a in &self.set_a {
            for b in &self.set_b {
                sum_cell = Some(config.assign_comparison(
                    layouter.namespace(|| format!("comparison {}", row)),
                    *a,
                    *b,
                    sum_cell.clone(),
                    row,
                )?);
                row += 1;
            }
        }

        // Expose the final sum as a public input
        if let Some(final_sum) = sum_cell {
            layouter.constrain_instance(final_sum.cell(), config.instance, 0)?;
        }

        Ok(())
    }
}

/// Simplified setup function for EqAffine curve
pub fn setup_eq(k: u32) -> Result<Halo2Setup<EqAffine>, Error> {
    let params = halo2_proofs::poly::commitment::Params::<EqAffine>::new(k);
    let empty_circuit = PsiCircuit::default();

    let vk = keygen_vk(&params, &empty_circuit)?;
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit)?;

    Ok((params, pk, vk))
}

/// Generate a proof for the PSI circuit
pub fn generate_proof(
    params: &halo2_proofs::poly::commitment::Params<EqAffine>,
    pk: &ProvingKey<EqAffine>,
    circuit: PsiCircuit,
    public_inputs: &[Fp],
) -> Result<Vec<u8>, Error> {
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);

    create_proof(
        params,
        pk,
        &[circuit],
        &[&[public_inputs]],
        OsRng,
        &mut transcript,
    )?;

    Ok(transcript.finalize())
}

/// Verify a proof for the PSI circuit
pub fn verify_proof(
    params: &halo2_proofs::poly::commitment::Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
    proof: &[u8],
    public_inputs: &[Fp],
) -> Result<(), Error> {
    let strategy = halo2_proofs::plonk::SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(proof);

    halo2_verify_proof(params, vk, strategy, &[&[public_inputs]], &mut transcript)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_to_field() {
        let h1 = hash_to_field(42);
        let h2 = hash_to_field(42);
        let h3 = hash_to_field(43);

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_intersection_computation() {
        let set_a = vec![hash_to_field(1), hash_to_field(2), hash_to_field(3)];
        let set_b = vec![hash_to_field(2), hash_to_field(3), hash_to_field(4)];

        let circuit = PsiCircuit::new(set_a, set_b, 2);
        assert_eq!(circuit.compute_intersection_size(), 2);
    }

    #[test]
    fn test_full_proof_verification_flow() {
        let set_a = vec![hash_to_field(1), hash_to_field(2)];
        let set_b = vec![hash_to_field(2), hash_to_field(3)];

        let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
        let intersection_size = circuit.compute_intersection_size();
        assert_eq!(intersection_size, 1);

        let k = 10;
        let (params, pk, vk) = setup_eq(k).unwrap();

        let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
        let public_inputs = vec![Fp::from(intersection_size)];

        let proof = generate_proof(&params, &pk, circuit, &public_inputs).unwrap();
        verify_proof(&params, &vk, &proof, &public_inputs).unwrap();
    }
}
