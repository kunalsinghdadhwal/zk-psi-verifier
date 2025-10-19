use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use pasta_curves::Fp;
use zk_psi_verifier::{generate_proof, hash_to_field, setup_eq, verify_proof, PsiCircuit};

fn bench_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_generation");

    for size in [4, 8, 16].iter() {
        let set_a: Vec<Fp> = (1..=*size).map(|i| hash_to_field(i as u64)).collect();
        let set_b: Vec<Fp> = ((*size / 2)..=(*size + *size / 2))
            .map(|i| hash_to_field(i as u64))
            .collect();

        let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
        let intersection_size = circuit.compute_intersection_size();

        let k = 12;
        let (params, pk, _vk) = setup_eq(k).expect("Setup failed");

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}x{}", size, size)),
            size,
            |b, _| {
                b.iter(|| {
                    let circuit = PsiCircuit::new(
                        black_box(set_a.clone()),
                        black_box(set_b.clone()),
                        black_box(intersection_size),
                    );
                    let public_inputs = vec![Fp::from(intersection_size)];

                    generate_proof(
                        black_box(&params),
                        black_box(&pk),
                        black_box(circuit),
                        black_box(&public_inputs),
                    )
                    .expect("Proof generation failed")
                });
            },
        );
    }

    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_verification");

    for size in [4, 8, 16].iter() {
        let set_a: Vec<Fp> = (1..=*size).map(|i| hash_to_field(i as u64)).collect();
        let set_b: Vec<Fp> = ((*size / 2)..=(*size + *size / 2))
            .map(|i| hash_to_field(i as u64))
            .collect();

        let circuit = PsiCircuit::new(set_a.clone(), set_b.clone(), 0);
        let intersection_size = circuit.compute_intersection_size();

        let k = 12;
        let (params, pk, vk) = setup_eq(k).expect("Setup failed");

        let circuit = PsiCircuit::new(set_a, set_b, intersection_size);
        let public_inputs = vec![Fp::from(intersection_size)];
        let proof =
            generate_proof(&params, &pk, circuit, &public_inputs).expect("Proof generation failed");

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}x{}", size, size)),
            size,
            |b, _| {
                b.iter(|| {
                    verify_proof(
                        black_box(&params),
                        black_box(&vk),
                        black_box(&proof),
                        black_box(&public_inputs),
                    )
                    .expect("Verification failed")
                });
            },
        );
    }

    group.finish();
}

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("setup");

    for k in [10, 12, 14].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("k={}", k)),
            k,
            |b, &k| {
                b.iter(|| setup_eq(black_box(k)).expect("Setup failed"));
            },
        );
    }

    group.finish();
}

fn bench_intersection_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("intersection_computation");

    for size in [4, 8, 16, 32].iter() {
        let set_a: Vec<Fp> = (1..=*size).map(|i| hash_to_field(i as u64)).collect();
        let set_b: Vec<Fp> = ((*size / 2)..=(*size + *size / 2))
            .map(|i| hash_to_field(i as u64))
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}x{}", size, size)),
            size,
            |b, _| {
                b.iter(|| {
                    let circuit = PsiCircuit::new(
                        black_box(set_a.clone()),
                        black_box(set_b.clone()),
                        black_box(0),
                    );
                    circuit.compute_intersection_size()
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_verification,
    bench_setup,
    bench_intersection_computation
);
criterion_main!(benches);
