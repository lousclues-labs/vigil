#![no_main]

use std::sync::atomic::{AtomicU64, Ordering};
use std::os::unix::fs::PermissionsExt;

use libfuzzer_sys::fuzz_target;
use vigil::wal::DetectionWal;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let mut path = std::env::temp_dir();
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    path.push(format!("vigil-fuzz-wal-{}-{}", std::process::id(), id));

    if std::fs::write(&path, data).is_ok() {
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        if let Ok(wal) = DetectionWal::open(&path, None, 64 * 1024 * 1024) {
            let _ = wal.iter_unconsumed();
        }
    }

    let _ = std::fs::remove_file(&path);
});
