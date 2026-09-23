use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

fn bench_blake3_hash_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3_hash_bytes");
    for &size in &[64 * 1024usize, 1_048_576, 16 * 1_048_576] {
        let data = vec![42u8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_function(format!("{}KiB", size / 1024), |b| {
            b.iter(|| {
                let out = vigil::hash::blake3_hash_bytes(black_box(&data));
                black_box(out);
            })
        });
    }
    group.finish();
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

/// Correlation over a realistic APT transaction: 22 packages, 42 detections,
/// three of which are unchanged symlinks resolving to replaced unit files.
///
/// Runs against fixture evidence rather than the live system, so the number is
/// the engine's own cost and is comparable across machines. Evidence
/// *collection* is measured separately by `vigil check` on a real box; it is
/// bounded by design (one batched ownership query, verification only for
/// packages a transaction names, size-capped tail reads of logs).
fn bench_correlation_engine(c: &mut Criterion) {
    use std::path::PathBuf;
    use std::sync::Arc;
    use vigil::correlate::{
        correlate, CorrelationInput, PackageAction, PackageTransition, TransactionRecord,
        TransactionSource, TransactionStatus,
    };
    use vigil::package::PackageVerification;
    use vigil::types::{Change, ChangeResult, Severity};

    const T0: i64 = 1_758_326_834;

    fn detection(path: &str, severity: Severity) -> ChangeResult {
        ChangeResult {
            path: Arc::new(PathBuf::from(path)),
            changes: vec![Change::ContentModified {
                old_hash: "old".into(),
                new_hash: "new".into(),
            }],
            severity,
            monitored_group: "system".into(),
            process: None,
            package: None,
            package_update: false,
            disambiguation: None,
        }
    }

    // 22 packages, 42 detections: the shape from a routine `apt upgrade`.
    let packages: Vec<String> = (0..22).map(|i| format!("package-{i:02}")).collect();
    let mut changes = Vec::new();
    let mut input = CorrelationInput::new();

    let mut tx = TransactionRecord::new(TransactionSource::Apt, T0);
    tx.end = Some(T0 + 2);
    tx.status = TransactionStatus::Completed;
    tx.command = Some("apt upgrade".into());

    for (i, package) in packages.iter().enumerate() {
        let mut transition = PackageTransition::new(package.as_str(), PackageAction::Upgrade)
            .with_versions(Some("1.0"), Some("1.1"));
        transition.installed_complete = Some(true);
        tx.packages.push(transition);
        input.installed.insert(package.clone(), "1.1".into());

        // Two files per package for the first 20, one for the rest: 42 total.
        let files = if i < 20 { 2 } else { 1 };
        for f in 0..files {
            let path = format!("/usr/lib/{package}/file{f}");
            changes.push(detection(&path, Severity::Critical));
            input
                .ownership
                .insert(PathBuf::from(&path), vec![package.clone()]);
            input
                .verification
                .insert(path.clone(), PackageVerification::Verified);
            input
                .observed_change_time
                .insert(PathBuf::from(&path), T0 + 1);
        }
    }
    tx.normalize();
    input.transactions.push(tx);

    c.bench_function("correlate_apt_22pkg_42detections", |b| {
        b.iter(|| {
            let result = correlate(black_box(&changes), black_box(&input));
            black_box(result.events.len());
        })
    });

    // A large transaction: 500 packages, 2000 detections.
    let mut big_changes = Vec::new();
    let mut big_input = CorrelationInput::new();
    let mut big_tx = TransactionRecord::new(TransactionSource::Apt, T0);
    big_tx.end = Some(T0 + 60);
    big_tx.status = TransactionStatus::Completed;

    for i in 0..500 {
        let package = format!("bulk-{i:04}");
        let mut transition = PackageTransition::new(package.as_str(), PackageAction::Upgrade)
            .with_versions(Some("1.0"), Some("1.1"));
        transition.installed_complete = Some(true);
        big_tx.packages.push(transition);
        big_input.installed.insert(package.clone(), "1.1".into());
        for f in 0..4 {
            let path = format!("/usr/lib/{package}/file{f}");
            big_changes.push(detection(&path, Severity::Critical));
            big_input
                .ownership
                .insert(PathBuf::from(&path), vec![package.clone()]);
            big_input
                .verification
                .insert(path.clone(), PackageVerification::Verified);
            big_input
                .observed_change_time
                .insert(PathBuf::from(&path), T0 + 5);
        }
    }
    big_tx.normalize();
    big_input.transactions.push(big_tx);

    c.bench_function("correlate_apt_500pkg_2000detections", |b| {
        b.iter(|| {
            let result = correlate(black_box(&big_changes), black_box(&big_input));
            black_box(result.events.len());
        })
    });
}

/// Snapshot diff for a symlink whose target was replaced.
///
/// The alias-attribution path added for symlink object tracking runs inside
/// `diff`, which the scanner calls for every changed file, so it is worth
/// keeping an eye on.
fn bench_symlink_alias_diff(c: &mut Criterion) {
    use std::path::PathBuf;
    use vigil::types::{
        BaselineEntry, BaselineSource, ContentFingerprint, FileIdentity, FileSnapshot, FileType,
        PermissionState, SecurityState,
    };

    let identity = |inode: u64| FileIdentity {
        inode,
        device: 1,
        file_type: FileType::Symlink,
        symlink_target: Some(PathBuf::from("/lib/systemd/system/rsyslog.service")),
        link_text: Some(PathBuf::from("/lib/systemd/system/rsyslog.service")),
        link_inode: Some(4242),
        link_device: Some(1),
    };

    let baseline = BaselineEntry {
        id: None,
        path: PathBuf::from("/etc/systemd/system/multi-user.target.wants/rsyslog.service"),
        identity: identity(100),
        content: ContentFingerprint {
            hash: "old".into(),
            size: 10,
        },
        permissions: PermissionState {
            mode: 0o644,
            owner_uid: 0,
            owner_gid: 0,
            capabilities: None,
        },
        security: SecurityState::default(),
        mtime: 1,
        package: None,
        source: BaselineSource::AutoScan,
        added_at: 1,
        updated_at: 1,
    };

    let snapshot = FileSnapshot {
        path: baseline.path.clone(),
        identity: identity(200),
        content: ContentFingerprint {
            hash: "new".into(),
            size: 12,
        },
        permissions: baseline.permissions.clone(),
        security: SecurityState::default(),
        mtime: 2,
    };

    c.bench_function("symlink_alias_diff", |b| {
        b.iter(|| {
            let changes = black_box(&snapshot).diff(black_box(&baseline));
            black_box(changes.len());
        })
    });
}

criterion_group!(
    benches,
    bench_blake3_hash_bytes,
    bench_exclusion_filter,
    bench_correlation_engine,
    bench_symlink_alias_diff
);
criterion_main!(benches);
