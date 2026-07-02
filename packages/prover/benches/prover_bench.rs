use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_merkle_insert(c: &mut Criterion) {
    c.bench_function("merkle_insert_32_depth", |b| {
        b.iter(|| {
            let mut tree =
                stellar_privacy_prover::MerkleTree::new(32);
            let leaf = ark_bn254::Fr::from(42u64);
            tree.insert(black_box(leaf));
        })
    });
}

fn bench_commitment(c: &mut Criterion) {
    use ark_bn254::Fr;
    use stellar_privacy_prover::circuit::compute_commitment;

    c.bench_function("compute_commitment", |b| {
        b.iter(|| {
            let secret = Fr::from(12345u64);
            let recipient = Fr::from(67890u64);
            let amount = Fr::from(1000u64);
            black_box(compute_commitment(secret, recipient, amount));
        })
    });
}

criterion_group!(benches, bench_merkle_insert, bench_commitment);
criterion_main!(benches);
