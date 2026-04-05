use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_blake3_hash_bytes(c: &mut Criterion) {
    let data = vec![42u8; 1_048_576];

    c.bench_function("blake3_hash_bytes_1MB", |b| {
        b.iter(|| {
            let out = vigil::hash::blake3_hash_bytes(black_box(&data));
            black_box(out);
        })
    });
}

fn bench_exclusion_filter(c: &mut Criterion) {
    let mut cfg = vigil::config::default_config();
    cfg.exclusions.patterns = (0..200).map(|i| format!("**/*.tmp{}", i)).collect();

    let filter = vigil::filter::exclusion::ExclusionFilter::new(&cfg);

    c.bench_function("event_filter_10k", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for i in 0..10_000 {
                let path = format!("/tmp/test-{}.txt", i);
                if filter.is_excluded(black_box(&path)) {
                    hits += 1;
                }
            }
            black_box(hits);
        })
    });
}

criterion_group!(benches, bench_blake3_hash_bytes, bench_exclusion_filter);
criterion_main!(benches);
