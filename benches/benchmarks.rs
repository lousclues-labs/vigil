use std::collections::HashMap;
use std::fs::File;
use std::io::Write;

use criterion::{black_box, BenchmarkId, Criterion};

use vigil::baseline::hash::{blake3_hash_bytes, blake3_hash_file};
use vigil::config::{Config, WatchGroup};
use vigil::monitor::filter::EventFilter;
use vigil::types::{BaselineEntry, BaselineSource, FsEvent, FsEventType, Severity};
use vigil::watch_index::WatchGroupIndex;

// ── blake3_hash_file with varying sizes ────────────────────

fn bench_blake3_hash_file(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash_file");

    for &size in &[1_024, 1_048_576, 104_857_600] {
        let label = match size {
            1_024 => "1KB",
            1_048_576 => "1MB",
            104_857_600 => "100MB",
            _ => "unknown",
        };

        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join(format!("bench-{}.bin", label));
        {
            let mut f = File::create(&path).expect("create bench file");
            // Write in chunks to avoid allocating 100MB at once
            let chunk = vec![0xABu8; 65_536];
            let mut remaining = size;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                f.write_all(&chunk[..n]).expect("write chunk");
                remaining -= n;
            }
            f.flush().expect("flush");
        }

        let file = File::open(&path).expect("open bench file");

        group.bench_with_input(BenchmarkId::from_parameter(label), &file, |b, file| {
            b.iter(|| blake3_hash_file(black_box(file)).expect("hash"))
        });
    }

    group.finish();
}

// ── blake3_hash_bytes (baseline comparison) ────────────────

fn bench_blake3_hash_bytes(c: &mut Criterion) {
    let data = vec![0xCDu8; 1_048_576]; // 1MB
    c.bench_function("blake3_hash_bytes_1MB", |b| {
        b.iter(|| blake3_hash_bytes(black_box(&data)))
    });
}

// ── compare_entry benchmarks ───────────────────────────────

fn bench_compare_entry(c: &mut Criterion) {
    use vigil::compare::compare_entry;

    let dir = tempfile::tempdir().expect("create temp dir");

    // Unchanged file
    let unchanged_path = dir.path().join("unchanged.txt");
    std::fs::write(&unchanged_path, b"stable content").expect("write");
    let unchanged_meta = std::fs::metadata(&unchanged_path).expect("metadata");
    let unchanged_hash = blake3_hash_bytes(b"stable content");

    let mut watch = HashMap::new();
    watch.insert(
        "bench".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec![dir.path().to_string_lossy().into_owned()],
        },
    );

    let config = Config {
        daemon: Default::default(),
        scanner: Default::default(),
        alerts: Default::default(),
        exclusions: Default::default(),
        package_manager: Default::default(),
        hooks: Default::default(),
        security: Default::default(),
        database: Default::default(),
        watch,
    };

    let baseline_unchanged = {
        use std::os::unix::fs::MetadataExt;
        BaselineEntry {
            id: Some(1),
            path: unchanged_path.clone(),
            hash: unchanged_hash.clone(),
            size: unchanged_meta.len(),
            permissions: unchanged_meta.mode(),
            owner_uid: unchanged_meta.uid(),
            owner_gid: unchanged_meta.gid(),
            mtime: unchanged_meta.mtime(),
            inode: unchanged_meta.ino(),
            device: unchanged_meta.dev(),
            xattrs: "{}".into(),
            security_context: String::new(),
            package: None,
            source: BaselineSource::Manual,
            added_at: 0,
            updated_at: 0,
        }
    };

    c.bench_function("compare_entry_unchanged", |b| {
        b.iter(|| {
            compare_entry(
                black_box(&baseline_unchanged),
                black_box(&config),
                Severity::High,
                "bench",
                false,
            )
        })
    });

    // Modified file
    let modified_path = dir.path().join("modified.txt");
    std::fs::write(&modified_path, b"new content").expect("write");
    let modified_meta = std::fs::metadata(&modified_path).expect("metadata");

    let baseline_modified = {
        use std::os::unix::fs::MetadataExt;
        BaselineEntry {
            id: Some(2),
            path: modified_path.clone(),
            hash: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            size: modified_meta.len(),
            permissions: modified_meta.mode(),
            owner_uid: modified_meta.uid(),
            owner_gid: modified_meta.gid(),
            mtime: modified_meta.mtime(),
            inode: modified_meta.ino(),
            device: modified_meta.dev(),
            xattrs: "{}".into(),
            security_context: String::new(),
            package: None,
            source: BaselineSource::Manual,
            added_at: 0,
            updated_at: 0,
        }
    };

    c.bench_function("compare_entry_modified", |b| {
        b.iter(|| {
            compare_entry(
                black_box(&baseline_modified),
                black_box(&config),
                Severity::High,
                "bench",
                false,
            )
        })
    });

    // Deleted file
    let deleted_path = dir.path().join("deleted.txt");
    let baseline_deleted = BaselineEntry {
        id: Some(3),
        path: deleted_path,
        hash: "aaaa".into(),
        size: 100,
        permissions: 0o644,
        owner_uid: 1000,
        owner_gid: 1000,
        mtime: 0,
        inode: 99999,
        device: 0,
        xattrs: "{}".into(),
        security_context: String::new(),
        package: None,
        source: BaselineSource::Manual,
        added_at: 0,
        updated_at: 0,
    };

    c.bench_function("compare_entry_deleted", |b| {
        b.iter(|| {
            compare_entry(
                black_box(&baseline_deleted),
                black_box(&config),
                Severity::High,
                "bench",
                false,
            )
        })
    });
}

// ── EventFilter::should_process with hot debounce map ──────

fn bench_event_filter(c: &mut Criterion) {
    let mut watch = HashMap::new();
    watch.insert(
        "bench".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec!["/tmp/bench/".into()],
        },
    );

    let config = Config {
        daemon: Default::default(),
        scanner: Default::default(),
        alerts: Default::default(),
        exclusions: Default::default(),
        package_manager: Default::default(),
        hooks: Default::default(),
        security: Default::default(),
        database: Default::default(),
        watch,
    };

    let mut filter = EventFilter::new(&config);

    // Pre-populate the debounce map with 10K entries
    for i in 0..10_000 {
        let event = FsEvent {
            path: format!("/tmp/bench/file_{}.txt", i).into(),
            event_type: FsEventType::Modify,
            timestamp: chrono::Utc::now(),
        };
        filter.should_process(&event);
    }

    // Now benchmark a new event (not in debounce map)
    let fresh_event = FsEvent {
        path: "/tmp/bench/new_file.txt".into(),
        event_type: FsEventType::Modify,
        timestamp: chrono::Utc::now(),
    };

    c.bench_function("event_filter_10k_debounce", |b| {
        b.iter(|| filter.should_process(black_box(&fresh_event)))
    });
}

// ── Full scan throughput ───────────────────────────────────

fn bench_full_scan(c: &mut Criterion) {
    use vigil::db;

    let dir = tempfile::tempdir().expect("create temp dir");
    let db_path = dir.path().join("bench.db");

    let mut watch = HashMap::new();
    watch.insert(
        "bench".into(),
        WatchGroup {
            severity: Severity::High,
            paths: vec![dir.path().to_string_lossy().into_owned() + "/"],
        },
    );

    let config = Config {
        daemon: vigil::config::DaemonConfig {
            db_path: db_path.clone(),
            ..Default::default()
        },
        scanner: Default::default(),
        alerts: vigil::config::AlertsConfig {
            desktop_notifications: false,
            syslog: false,
            ..Default::default()
        },
        exclusions: Default::default(),
        package_manager: Default::default(),
        hooks: Default::default(),
        security: Default::default(),
        database: Default::default(),
        watch,
    };

    // Create N test files
    let n = 100;
    for i in 0..n {
        let path = dir.path().join(format!("scan_file_{}.txt", i));
        std::fs::write(&path, format!("content {}", i)).expect("write test file");
    }

    // Initialize baseline
    let conn = db::open_db(&config).expect("open db");
    vigil::baseline::init_baseline(&conn, &config, false).expect("init baseline");

    let alert_engine = vigil::alert::AlertEngine::new(&config).expect("alert engine");

    c.bench_function("full_scan_100_entries", |b| {
        b.iter(|| {
            vigil::scanner::run_scan(
                &conn,
                black_box(&config),
                &alert_engine,
                vigil::types::ScanMode::Full,
                None,
            )
            .expect("scan")
        })
    });
}

// ── WatchGroupIndex lookup benchmarks ──────────────────────

fn bench_watch_group_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("watch_group_lookup");

    for &count in &[100, 1000] {
        let entries: Vec<(std::path::PathBuf, String, Severity)> = (0..count)
            .map(|i| {
                (
                    std::path::PathBuf::from(format!("/watch/path_{}/", i)),
                    format!("group_{}", i),
                    Severity::High,
                )
            })
            .collect();

        let index = WatchGroupIndex::from_expanded(entries);

        // Lookup a path that matches one of the middle entries
        let target = std::path::Path::new("/watch/path_50/some/deep/file.txt");

        group.bench_with_input(BenchmarkId::from_parameter(count), &index, |b, index| {
            b.iter(|| index.lookup(black_box(target)))
        });
    }

    group.finish();
}

fn main() {
    // When benchmarks are executed through `cargo test --all-targets -- --test-threads=N`,
    // libtest-only flags are forwarded to bench binaries. Criterion rejects those flags.
    // In that case, run with defaults instead of parsing CLI args.
    let has_libtest_args = std::env::args().any(|arg| {
        arg.starts_with("--test-threads")
            || arg == "--nocapture"
            || arg == "--show-output"
            || arg.starts_with("--format")
    });

    let mut c = if has_libtest_args {
        Criterion::default()
    } else {
        Criterion::default().configure_from_args()
    };

    bench_blake3_hash_file(&mut c);
    bench_blake3_hash_bytes(&mut c);
    bench_compare_entry(&mut c);
    bench_event_filter(&mut c);
    bench_full_scan(&mut c);
    bench_watch_group_lookup(&mut c);
    c.final_summary();
}
