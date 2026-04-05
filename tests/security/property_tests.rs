// Property-based tests for Vigil comparison invariants.

use proptest::prelude::*;
use std::io::Write;
use std::path::PathBuf;

use vigil::baseline::hash::{blake3_hash_bytes, blake3_hash_file};
use vigil::db;
use vigil::types::{BaselineEntry, BaselineSource, Severity};

// Roundtrip: any BaselineEntry written to DB then read back has identical fields.
proptest! {
    #[test]
    fn baseline_db_roundtrip(
        path in "[a-z/]{1,64}",
        hash in "[a-f0-9]{64}",
        size in 0u64..u64::MAX,
        permissions in 0u32..0o177777u32,
        owner_uid in 0u32..65535u32,
        owner_gid in 0u32..65535u32,
        mtime in 0i64..i64::MAX,
    ) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        db::schema::create_tables(&conn).unwrap();

        let entry = BaselineEntry {
            id: None,
            path: PathBuf::from(&path),
            hash: hash.clone(),
            size,
            permissions,
            owner_uid,
            owner_gid,
            mtime,
            inode: 12345,
            device: 1,
            xattrs: "{}".into(),
            security_context: String::new(),
            package: None,
            source: BaselineSource::AutoScan,
            added_at: 1700000000,
            updated_at: 1700000000,
        };

        db::ops::upsert_baseline(&conn, &entry).unwrap();

        let retrieved = db::ops::get_baseline_by_path(&conn, &path)
            .unwrap()
            .expect("entry should exist");

        prop_assert_eq!(&retrieved.hash, &hash);
        prop_assert_eq!(retrieved.size, size);
        prop_assert_eq!(retrieved.permissions, permissions);
        prop_assert_eq!(retrieved.owner_uid, owner_uid);
        prop_assert_eq!(retrieved.owner_gid, owner_gid);
        prop_assert_eq!(retrieved.mtime, mtime);
    }
}

// Determinism: blake3 hash of same content always returns same result.
proptest! {
    #[test]
    fn blake3_deterministic(content in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let h1 = blake3_hash_bytes(&content);
        let h2 = blake3_hash_bytes(&content);
        prop_assert_eq!(h1, h2);
    }
}

// blake3_hash_file matches blake3_hash_bytes for the same content.
proptest! {
    #[test]
    fn blake3_file_matches_bytes(content in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test-file");
        {
            let mut f = std::fs::File::create(&file_path).unwrap();
            f.write_all(&content).unwrap();
            f.flush().unwrap();
        }

        let file = std::fs::File::open(&file_path).unwrap();
        let file_hash = blake3_hash_file(&file).unwrap();
        let bytes_hash = blake3_hash_bytes(&content);
        prop_assert_eq!(file_hash, bytes_hash);
    }
}

// Severity ordering: distinct values always have distinct Display output.
proptest! {
    #[test]
    fn severity_no_display_collisions(a in 0u8..4, b in 0u8..4) {
        let sev_a = match a {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        };
        let sev_b = match b {
            0 => Severity::Low,
            1 => Severity::Medium,
            2 => Severity::High,
            _ => Severity::Critical,
        };

        if a < b {
            prop_assert!(sev_a < sev_b);
            prop_assert_ne!(sev_a.to_string(), sev_b.to_string());
        }
    }
}
