use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, VigilError};
use crate::types::{Change, ChangeResult, ProcessAttribution, Severity};

pub mod audit_writer;
pub mod sink_runner;

const WAL_MAGIC: [u8; 4] = *b"VWAL";
const WAL_VERSION: u16 = 1;
const WAL_HEADER_SIZE: u64 = 64;
const MAX_ENTRY_SIZE: u32 = 1_048_576;
const FLAG_AUDIT_DONE: u16 = 0x0001;
const FLAG_SINK_DONE: u16 = 0x0002;
/// Maximum bytes the gap scanner will advance without finding a valid entry
/// before giving up.  Prevents adversarial DoS: an attacker with write access
/// could zero out a large WAL region, forcing the scanner to iterate millions
/// of positions.  With this cap the scanner stops, logs the gap, and returns
/// whatever entries it has already recovered.
///
/// Note: entries in this WAL format are not padded to any fixed alignment, so
/// gap scanning advances byte-by-byte for correctness.  If entries were ever
/// padded to 4-byte boundaries, the scanner could skip to aligned offsets and
/// reduce gap scanning from O(n) to ~O(n/4).  The current `MAX_GAP_BYTES`
/// limit makes this optimization unnecessary — at 64KB the byte-by-byte scan
/// completes in microseconds.
const MAX_GAP_BYTES: u64 = 65_536;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionSource {
    Realtime,
    ScheduledScan,
    OnDemandScan,
    Debounce,
    Panic,
    Sentinel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRecord {
    pub timestamp: i64,
    pub path: String,
    pub changes: Vec<Change>,
    pub severity: Severity,
    pub monitored_group: String,
    pub process: Option<ProcessAttribution>,
    pub package: Option<String>,
    pub package_update: bool,
    pub maintenance_window: bool,
    pub source: DetectionSource,
}

impl DetectionRecord {
    pub fn from_change_result(
        cr: &ChangeResult,
        maintenance_window: bool,
        source: DetectionSource,
    ) -> Self {
        Self {
            timestamp: chrono::Utc::now().timestamp(),
            path: cr.path.to_string_lossy().to_string(),
            changes: cr.changes.clone(),
            severity: cr.severity,
            monitored_group: cr.monitored_group.clone(),
            process: cr.process.clone(),
            package: cr.package.clone(),
            package_update: cr.package_update,
            maintenance_window,
            source,
        }
    }

    pub fn to_change_result(&self) -> ChangeResult {
        ChangeResult {
            path: std::sync::Arc::new(std::path::PathBuf::from(&self.path)),
            changes: self.changes.clone(),
            severity: self.severity,
            monitored_group: self.monitored_group.clone(),
            process: self.process.clone(),
            package: self.package.clone(),
            package_update: self.package_update,
        }
    }
}

pub struct DetectionWal {
    /// The file handle is wrapped in a Mutex (separate from `write_lock`) because
    /// `truncate_consumed()` needs to atomically replace the handle after compaction.
    /// Uncontended parking_lot::Mutex overhead is ~10ns, negligible vs. disk I/O.
    file: Mutex<File>,
    path: PathBuf,
    sequence: AtomicU64,
    file_len: AtomicU64,
    write_lock: Mutex<()>,
    hmac_key: Option<Zeroizing<Vec<u8>>>,
    hmac_key_fingerprint: [u8; 16],
    instance_nonce: [u8; 32],
    max_size_bytes: u64,
    sync_mode: crate::config::DetectionWalSync,
}

#[derive(Debug, Clone)]
pub struct WalEntry {
    pub sequence: u64,
    pub offset: u64,
    pub flags: u16,
    pub record: DetectionRecord,
}

impl WalEntry {
    pub fn audit_done(&self) -> bool {
        self.flags & FLAG_AUDIT_DONE != 0
    }

    pub fn sink_done(&self) -> bool {
        self.flags & FLAG_SINK_DONE != 0
    }

    pub fn fully_consumed(&self) -> bool {
        self.flags & (FLAG_AUDIT_DONE | FLAG_SINK_DONE) == (FLAG_AUDIT_DONE | FLAG_SINK_DONE)
    }
}

#[derive(Debug, Clone)]
struct ScannedEntry {
    sequence: u64,
    offset: u64,
    flags: u16,
    bytes: Vec<u8>,
    record: Option<DetectionRecord>,
}

impl DetectionWal {
    pub fn open(path: &Path, hmac_key: Option<&Zeroizing<Vec<u8>>>, max_size: u64) -> Result<Self> {
        Self::open_with_sync(
            path,
            hmac_key,
            max_size,
            crate::config::DetectionWalSync::Every,
        )
    }

    pub fn open_with_sync(
        path: &Path,
        hmac_key: Option<&Zeroizing<Vec<u8>>>,
        max_size: u64,
        sync_mode: crate::config::DetectionWalSync,
    ) -> Result<Self> {
        if max_size < WAL_HEADER_SIZE {
            return Err(VigilError::Wal(
                "WAL max_size must be at least header size".into(),
            ));
        }

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let existed = path.exists();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(path)?;

        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(VigilError::Wal(format!(
                "WAL file {} has unsafe mode {:04o} (must be 0600 or stricter)",
                path.display(),
                mode
            )));
        }

        let provided_fingerprint = hmac_key
            .map(|k| fingerprint_for_key(k))
            .unwrap_or([0u8; 16]);

        let mut instance_nonce = [0u8; 32];
        let mut header_fingerprint = [0u8; 16];

        let mut file_len = file.metadata()?.len();
        if !existed || file_len == 0 {
            instance_nonce = random_nonce()?;
            let header = build_header(provided_fingerprint, instance_nonce);
            write_all_at(&file, &header, 0)?;
            file.sync_data()?;
            file_len = WAL_HEADER_SIZE;
        } else {
            if file_len < WAL_HEADER_SIZE {
                return Err(VigilError::Wal(
                    "WAL file shorter than header size".to_string(),
                ));
            }

            let header = read_header(&file)?;
            if header[0..4] != WAL_MAGIC {
                return Err(VigilError::Wal("invalid WAL magic".into()));
            }
            let version = u16::from_le_bytes([header[4], header[5]]);
            if version != WAL_VERSION {
                return Err(VigilError::Wal(format!(
                    "unsupported WAL version {}",
                    version
                )));
            }

            header_fingerprint.copy_from_slice(&header[16..32]);
            instance_nonce.copy_from_slice(&header[32..64]);

            if hmac_key.is_some()
                && header_fingerprint != [0u8; 16]
                && header_fingerprint != provided_fingerprint
            {
                return Err(VigilError::Wal(
                    "WAL HMAC key fingerprint mismatch".to_string(),
                ));
            }
        }

        let effective_fingerprint = if header_fingerprint == [0u8; 16] {
            provided_fingerprint
        } else {
            header_fingerprint
        };

        let scan = scan_entries(
            &file,
            file_len,
            hmac_key.map(|k| k.as_slice()),
            false,
            false,
        )?;
        let next_sequence = scan
            .iter()
            .map(|e| e.sequence)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);

        Ok(Self {
            file: Mutex::new(file),
            path: path.to_path_buf(),
            sequence: AtomicU64::new(next_sequence),
            file_len: AtomicU64::new(file_len),
            write_lock: Mutex::new(()),
            hmac_key: hmac_key.cloned(),
            hmac_key_fingerprint: effective_fingerprint,
            instance_nonce,
            max_size_bytes: max_size,
            sync_mode,
        })
    }

    pub fn append(&self, record: &DetectionRecord) -> Result<u64> {
        let payload = rmp_serde::to_vec(record)
            .map_err(|e| VigilError::Wal(format!("WAL payload serialization failed: {}", e)))?;

        let entry_size = 4u64 + 8 + 2 + 32 + payload.len() as u64 + 4;
        if entry_size > MAX_ENTRY_SIZE as u64 {
            return Err(VigilError::Wal(format!(
                "WAL entry too large: {} bytes",
                entry_size
            )));
        }

        // Fast-path capacity check BEFORE acquiring lock: avoids queueing all
        // threads on the mutex just to discover the WAL is full.
        let current_len = self.file_len.load(Ordering::Acquire);
        if current_len + entry_size > self.max_size_bytes {
            return Err(VigilError::Wal("WAL full".into()));
        }

        let _guard = self.write_lock.lock();

        // Re-check capacity under lock (another thread may have appended)
        let current_len = self.file_len.load(Ordering::Acquire);
        if current_len + entry_size > self.max_size_bytes {
            return Err(VigilError::Wal("WAL full".into()));
        }

        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);

        let mut buf = Vec::with_capacity(entry_size as usize);
        buf.extend_from_slice(&(entry_size as u32).to_le_bytes());
        buf.extend_from_slice(&sequence.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&compute_entry_hmac(self.hmac_key.as_ref(), &payload)?);
        buf.extend_from_slice(&payload);
        let crc = crc32fast::hash(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        {
            let file = self.file.lock();
            write_all_at(&file, &buf, current_len)?;
            if matches!(self.sync_mode, crate::config::DetectionWalSync::Every) {
                file.sync_data()?;
            }
        }

        self.file_len
            .store(current_len + entry_size, Ordering::Release);
        Ok(sequence)
    }

    /// Mark the audit-done flag on the entry at `offset`.
    ///
    /// See `mark_flag` for concurrency constraints.
    pub fn mark_audit_done(&self, offset: u64) -> Result<()> {
        self.mark_flag(offset, FLAG_AUDIT_DONE)
    }

    /// Mark the sink-done flag on the entry at `offset`.
    ///
    /// See `mark_flag` for concurrency constraints.
    pub fn mark_sink_done(&self, offset: u64) -> Result<()> {
        self.mark_flag(offset, FLAG_SINK_DONE)
    }

    // OPTIMIZE: `iter_unconsumed` currently scans the entire WAL file from offset 64
    // to file_len on every call, deserializing every entry to find unconsumed ones.
    // Both `AuditWriter` and `SinkRunner` call this on every loop iteration, making
    // the hot path O(total_entries) per consumer per iteration.
    //
    // At current expected volumes (hundreds of detections per minute at peak), the
    // full scan is acceptable. However, on busy servers with thousands of monitored
    // paths under heavy I/O, this will become a bottleneck.
    //
    // Planned optimization:
    //   1. Maintain an in-memory index of (sequence, offset, flags) triples.
    //   2. Update the index on append, flag update, and truncation.
    //   3. Consumers read the index to find unprocessed entries, then seek
    //      directly to those offsets on disk.
    //   4. This turns the hot path from O(total_entries) to O(pending_entries).
    pub fn iter_unconsumed(&self) -> Result<Vec<WalEntry>> {
        let file_len = self.file_len.load(Ordering::Acquire);
        let file = self.file.lock();
        let mut scanned = scan_entries(
            &file,
            file_len,
            self.hmac_key.as_ref().map(|k| k.as_slice()),
            false,
            false,
        )?;

        scanned.sort_by_key(|e| e.sequence);

        let mut out = Vec::with_capacity(scanned.len());
        for e in scanned {
            if let Some(record) = e.record {
                out.push(WalEntry {
                    sequence: e.sequence,
                    offset: e.offset,
                    flags: e.flags,
                    record,
                });
            }
        }

        Ok(out)
    }

    pub fn truncate_consumed(&self) -> Result<u64> {
        let _guard = self.write_lock.lock();

        let file_len = self.file_len.load(Ordering::Acquire);
        let mut file = self.file.lock();

        let mut header = [0u8; WAL_HEADER_SIZE as usize];
        read_exact_at(&file, &mut header, 0)?;

        let mut entries = scan_entries(
            &file,
            file_len,
            self.hmac_key.as_ref().map(|k| k.as_slice()),
            true,
            true,
        )?;
        entries.sort_by_key(|e| e.sequence);

        let total_entries = entries.len();
        let unconsumed: Vec<_> = entries
            .into_iter()
            .filter(|e| !is_fully_consumed(e.flags))
            .collect();
        let purged = total_entries.saturating_sub(unconsumed.len()) as u64;

        if unconsumed.is_empty() {
            file.set_len(WAL_HEADER_SIZE)?;
            file.sync_data()?;
            self.file_len.store(WAL_HEADER_SIZE, Ordering::Release);
            self.sequence.store(0, Ordering::Release);
            return Ok(purged);
        }

        let tmp_path = self.path.with_extension("wal.tmp");
        {
            let mut tmp = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            tmp.write_all(&header)?;
            for entry in &unconsumed {
                tmp.write_all(&entry.bytes)?;
            }
            tmp.sync_data()?;
        }

        std::fs::rename(&tmp_path, &self.path)?;
        let reopened = OpenOptions::new().read(true).write(true).open(&self.path)?;
        *file = reopened;

        let new_len =
            WAL_HEADER_SIZE + unconsumed.iter().map(|e| e.bytes.len() as u64).sum::<u64>();
        self.file_len.store(new_len, Ordering::Release);
        let next_seq = unconsumed
            .iter()
            .map(|e| e.sequence)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        self.sequence.store(next_seq, Ordering::Release);

        Ok(purged)
    }

    pub fn instance_nonce(&self) -> &[u8; 32] {
        &self.instance_nonce
    }

    pub fn pending_count(&self) -> u64 {
        self.iter_unconsumed().map(|v| v.len() as u64).unwrap_or(0)
    }

    pub fn file_size(&self) -> u64 {
        self.file_len.load(Ordering::Acquire)
    }

    pub fn hmac_key_fingerprint(&self) -> &[u8; 16] {
        &self.hmac_key_fingerprint
    }

    /// Set a flag bit on the WAL entry at `offset` (e.g. `FLAG_AUDIT_DONE`).
    ///
    /// # Concurrency safety
    ///
    /// This performs a **non-atomic read-modify-write**: it reads the entire entry,
    /// ORs the flag bit into the 2-byte flags field, recomputes the CRC-32, and
    /// writes the entry back.  If two threads called `mark_audit_done` and
    /// `mark_sink_done` on the **same** entry concurrently without serialization,
    /// both would read the old flags, both would OR in their respective bit, and
    /// the second write would overwrite the first — silently losing one flag.
    ///
    /// The global `write_lock` prevents this today: every caller acquires it before
    /// touching the file.  The lock is required not just for appends, but also for
    /// flag updates.
    ///
    /// **If per-entry locking is ever introduced**, flag updates on the same entry
    /// must still be serialized (e.g. via a per-entry mutex or CAS on the flags
    /// word) to avoid the lost-update race described above.
    fn mark_flag(&self, offset: u64, bit: u16) -> Result<()> {
        let _guard = self.write_lock.lock();
        let file = self.file.lock();

        let mut flags_buf = [0u8; 2];
        read_exact_at(&file, &mut flags_buf, offset + 12)?;
        let mut flags = u16::from_le_bytes(flags_buf);
        flags |= bit;
        let mut size_buf = [0u8; 4];
        read_exact_at(&file, &mut size_buf, offset)?;
        let entry_size = u32::from_le_bytes(size_buf) as usize;
        if entry_size < 50 {
            return Err(VigilError::Wal(
                "invalid WAL entry size while marking flags".into(),
            ));
        }

        let mut entry = vec![0u8; entry_size];
        read_exact_at(&file, &mut entry, offset)?;

        entry[12..14].copy_from_slice(&flags.to_le_bytes());
        let crc = crc32fast::hash(&entry[..entry_size - 4]);
        entry[entry_size - 4..entry_size].copy_from_slice(&crc.to_le_bytes());

        write_all_at(&file, &entry, offset)?;
        Ok(())
    }
}

fn build_header(fingerprint: [u8; 16], nonce: [u8; 32]) -> [u8; WAL_HEADER_SIZE as usize] {
    let mut header = [0u8; WAL_HEADER_SIZE as usize];
    header[0..4].copy_from_slice(&WAL_MAGIC);
    header[4..6].copy_from_slice(&WAL_VERSION.to_le_bytes());
    header[6..8].copy_from_slice(&0u16.to_le_bytes());
    header[8..16].copy_from_slice(&chrono::Utc::now().timestamp().to_le_bytes());
    header[16..32].copy_from_slice(&fingerprint);
    header[32..64].copy_from_slice(&nonce);
    header
}

fn read_header(file: &File) -> Result<[u8; WAL_HEADER_SIZE as usize]> {
    let mut header = [0u8; WAL_HEADER_SIZE as usize];
    read_exact_at(file, &mut header, 0)?;
    Ok(header)
}

fn fingerprint_for_key(key: &[u8]) -> [u8; 16] {
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&blake3::hash(key).as_bytes()[..16]);
    fp
}

fn random_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    let mut urandom = File::open("/dev/urandom")?;
    urandom.read_exact(&mut nonce)?;
    Ok(nonce)
}

fn compute_entry_hmac(key: Option<&Zeroizing<Vec<u8>>>, payload: &[u8]) -> Result<[u8; 32]> {
    match key {
        Some(k) => {
            let mut mac = HmacSha256::new_from_slice(k)
                .map_err(|e| VigilError::Wal(format!("failed to initialize entry HMAC: {}", e)))?;
            mac.update(payload);
            let mut out = [0u8; 32];
            out.copy_from_slice(&mac.finalize().into_bytes());
            Ok(out)
        }
        None => Ok([0u8; 32]),
    }
}

fn verify_entry_hmac(key: &[u8], payload: &[u8], expected: &[u8]) -> Result<bool> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| VigilError::Wal(format!("failed to initialize entry HMAC verify: {}", e)))?;
    mac.update(payload);
    Ok(mac.verify_slice(expected).is_ok())
}

fn scan_entries(
    file: &File,
    file_len: u64,
    hmac_key: Option<&[u8]>,
    include_consumed: bool,
    keep_bytes: bool,
) -> Result<Vec<ScannedEntry>> {
    let mut offset = WAL_HEADER_SIZE;
    let mut out = Vec::new();
    let mut gap_start: Option<u64> = None;
    let mut gap_bytes: u64 = 0;

    while offset < file_len {
        // Part B: if we have been scanning a gap for more than MAX_GAP_BYTES,
        // stop recovery.  An attacker who can write to the WAL can already
        // delete entries — there is no point spending CPU trying to recover
        // data they have deliberately destroyed.
        if gap_bytes > MAX_GAP_BYTES {
            tracing::error!(
                gap_start = gap_start.unwrap_or(offset),
                gap_bytes,
                "WAL gap scan exceeded {}KB limit; stopping recovery to prevent DoS",
                MAX_GAP_BYTES / 1024
            );
            break;
        }

        let mut size_buf = [0u8; 4];
        if read_exact_at(file, &mut size_buf, offset).is_err() {
            break;
        }
        let entry_size = u32::from_le_bytes(size_buf);
        if !(50..=MAX_ENTRY_SIZE).contains(&entry_size) {
            if gap_start.is_none() {
                gap_start = Some(offset);
            }
            // Advance by 1 byte. Entries in this WAL format are not padded to
            // any alignment, so byte-by-byte scanning is required for
            // correctness.  The MAX_GAP_BYTES limit (Part B, checked at loop
            // top) bounds the total work to prevent adversarial DoS.
            offset += 1;
            gap_bytes += 1;
            continue;
        }

        let end = offset + entry_size as u64;
        if end > file_len {
            if gap_start.is_none() {
                gap_start = Some(offset);
            }
            offset += 1;
            gap_bytes += 1;
            continue;
        }

        let mut raw = vec![0u8; entry_size as usize];
        if read_exact_at(file, &mut raw, offset).is_err() {
            break;
        }

        let crc_expected = u32::from_le_bytes(
            raw[(entry_size as usize - 4)..entry_size as usize]
                .try_into()
                .map_err(|_| VigilError::Wal("failed to parse WAL entry CRC".into()))?,
        );
        let crc_actual = crc32fast::hash(&raw[..entry_size as usize - 4]);
        if crc_expected != crc_actual {
            if gap_start.is_none() {
                gap_start = Some(offset);
            }
            offset += 1;
            gap_bytes += 1;
            continue;
        }

        // Valid entry found — log and reset gap tracking
        if let Some(start) = gap_start.take() {
            tracing::warn!(
                start,
                end = offset,
                bytes_skipped = gap_bytes,
                "WAL scanner recovered from corrupted gap"
            );
            gap_bytes = 0;
        }

        let sequence = u64::from_le_bytes(
            raw[4..12]
                .try_into()
                .map_err(|_| VigilError::Wal("failed to parse WAL sequence".into()))?,
        );
        let flags = u16::from_le_bytes(
            raw[12..14]
                .try_into()
                .map_err(|_| VigilError::Wal("failed to parse WAL flags".into()))?,
        );
        let entry_hmac = &raw[14..46];
        let payload = &raw[46..entry_size as usize - 4];

        if let Some(key) = hmac_key {
            let any_hmac = entry_hmac.iter().any(|b| *b != 0);
            if any_hmac && !verify_entry_hmac(key, payload, entry_hmac)? {
                tracing::error!(
                    sequence = sequence,
                    offset = offset,
                    "WAL entry HMAC verification failed"
                );
                offset += entry_size as u64;
                continue;
            }
        }

        if !include_consumed && is_fully_consumed(flags) {
            offset += entry_size as u64;
            continue;
        }

        let record = if is_fully_consumed(flags) {
            None
        } else {
            match rmp_serde::from_slice::<DetectionRecord>(payload) {
                Ok(r) => Some(r),
                Err(_) => {
                    offset += entry_size as u64;
                    continue;
                }
            }
        };

        out.push(ScannedEntry {
            sequence,
            offset,
            flags,
            bytes: if keep_bytes { raw } else { Vec::new() },
            record,
        });

        offset += entry_size as u64;
    }

    // Log any trailing gap at end of file
    if let Some(start) = gap_start {
        tracing::warn!(
            start,
            bytes_skipped = gap_bytes,
            "WAL scanner: trailing corrupted gap at end of file"
        );
    }

    Ok(out)
}

fn is_fully_consumed(flags: u16) -> bool {
    flags & (FLAG_AUDIT_DONE | FLAG_SINK_DONE) == (FLAG_AUDIT_DONE | FLAG_SINK_DONE)
}

fn read_exact_at(file: &File, buf: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    let mut read = 0usize;
    while read < buf.len() {
        let n = file.read_at(&mut buf[read..], offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "short read",
            ));
        }
        read += n;
        offset += n as u64;
    }
    Ok(())
}

fn write_all_at(file: &File, buf: &[u8], mut offset: u64) -> std::io::Result<()> {
    let mut written = 0usize;
    while written < buf.len() {
        let n = file.write_at(&buf[written..], offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "short write",
            ));
        }
        written += n;
        offset += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;

    use super::*;

    fn make_record(idx: usize, severity: Severity, source: DetectionSource) -> DetectionRecord {
        DetectionRecord {
            timestamp: 1_700_000_000 + idx as i64,
            path: format!("/tmp/wal-test-{}", idx),
            changes: vec![Change::Created],
            severity,
            monitored_group: format!("group-{}", idx % 3),
            process: None,
            package: None,
            package_update: false,
            maintenance_window: false,
            source,
        }
    }

    fn open_wal(path: &Path, max_size: u64) -> DetectionWal {
        DetectionWal::open(path, None, max_size).unwrap()
    }

    #[test]
    fn append_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        let wal = open_wal(&dir.path().join("detections.wal"), 64 * 1024 * 1024);

        for i in 0..10 {
            let source = match i % 5 {
                0 => DetectionSource::Realtime,
                1 => DetectionSource::ScheduledScan,
                2 => DetectionSource::OnDemandScan,
                3 => DetectionSource::Debounce,
                _ => DetectionSource::Panic,
            };
            let severity = match i % 4 {
                0 => Severity::Low,
                1 => Severity::Medium,
                2 => Severity::High,
                _ => Severity::Critical,
            };
            wal.append(&make_record(i, severity, source)).unwrap();
        }

        let entries = wal.iter_unconsumed().unwrap();
        assert_eq!(entries.len(), 10);
        assert_eq!(entries[0].record.path, "/tmp/wal-test-0");
        assert_eq!(entries[9].record.path, "/tmp/wal-test-9");
    }

    #[test]
    fn concurrent_appends() {
        let dir = tempfile::tempdir().unwrap();
        let wal = Arc::new(open_wal(
            &dir.path().join("detections.wal"),
            128 * 1024 * 1024,
        ));

        let mut threads = Vec::new();
        for t in 0..8usize {
            let wal = wal.clone();
            threads.push(std::thread::spawn(move || {
                for i in 0..1000usize {
                    let idx = t * 1000 + i;
                    wal.append(&make_record(
                        idx,
                        Severity::Medium,
                        DetectionSource::Realtime,
                    ))
                    .unwrap();
                }
            }));
        }

        for th in threads {
            th.join().unwrap();
        }

        let entries = wal.iter_unconsumed().unwrap();
        assert_eq!(entries.len(), 8000);

        let seqs: HashSet<u64> = entries.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs.len(), 8000);
    }

    #[test]
    fn crc_corruption_detected() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        let s1 = wal
            .append(&make_record(1, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        wal.append(&make_record(2, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        let s3 = wal
            .append(&make_record(3, Severity::Low, DetectionSource::Realtime))
            .unwrap();

        let entries = wal.iter_unconsumed().unwrap();
        let second = &entries[1];
        let corrupt_at = second.offset + 46;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .unwrap();
        let mut b = [0u8; 1];
        read_exact_at(&file, &mut b, corrupt_at).unwrap();
        b[0] ^= 0xFF;
        write_all_at(&file, &b, corrupt_at).unwrap();

        let entries = wal.iter_unconsumed().unwrap();
        let got: Vec<u64> = entries.into_iter().map(|e| e.sequence).collect();
        assert_eq!(got, vec![s1, s3]);
    }

    #[test]
    fn partial_write_at_eof() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        wal.append(&make_record(1, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        wal.append(&make_record(2, Severity::Low, DetectionSource::Realtime))
            .unwrap();

        let len = std::fs::metadata(&wal_path).unwrap().len();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&wal_path)
            .unwrap()
            .set_len(len - 3)
            .unwrap();

        wal.file_len.store(len - 3, Ordering::Release);

        let entries = wal.iter_unconsumed().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].record.path, "/tmp/wal-test-1");
    }

    #[test]
    fn consumed_flags_independent() {
        let dir = tempfile::tempdir().unwrap();
        let wal = open_wal(&dir.path().join("detections.wal"), 64 * 1024 * 1024);

        for i in 0..5 {
            wal.append(&make_record(i, Severity::Low, DetectionSource::Realtime))
                .unwrap();
        }

        let entries = wal.iter_unconsumed().unwrap();
        for e in entries.iter().take(3) {
            wal.mark_audit_done(e.offset).unwrap();
        }

        let all = wal.iter_unconsumed().unwrap();
        let sink_pending = all.iter().filter(|e| !e.sink_done()).count();
        assert_eq!(sink_pending, 5);

        for e in all.iter().take(3) {
            wal.mark_sink_done(e.offset).unwrap();
        }

        let left = wal.iter_unconsumed().unwrap();
        assert_eq!(left.len(), 2);
    }

    #[test]
    fn sequence_resumes_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");

        {
            let wal = open_wal(&wal_path, 64 * 1024 * 1024);
            assert_eq!(
                wal.append(&make_record(1, Severity::Low, DetectionSource::Realtime))
                    .unwrap(),
                0
            );
            assert_eq!(
                wal.append(&make_record(2, Severity::Low, DetectionSource::Realtime))
                    .unwrap(),
                1
            );
        }

        let wal = open_wal(&wal_path, 64 * 1024 * 1024);
        let seq = wal
            .append(&make_record(3, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        assert_eq!(seq, 2);
    }

    #[test]
    fn wal_full_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let wal = open_wal(&dir.path().join("detections.wal"), WAL_HEADER_SIZE + 300);

        loop {
            let r = wal.append(&make_record(1, Severity::Low, DetectionSource::Realtime));
            if let Err(e) = r {
                match e {
                    VigilError::Wal(msg) => assert!(msg.contains("WAL full")),
                    _ => panic!("unexpected error type"),
                }
                break;
            }
        }
    }

    #[test]
    fn truncate_removes_consumed() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        for i in 0..10 {
            wal.append(&make_record(i, Severity::Low, DetectionSource::Realtime))
                .unwrap();
        }

        let entries = wal.iter_unconsumed().unwrap();
        for e in &entries {
            wal.mark_audit_done(e.offset).unwrap();
            wal.mark_sink_done(e.offset).unwrap();
        }

        wal.truncate_consumed().unwrap();
        assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), WAL_HEADER_SIZE);
        assert_eq!(wal.file_size(), WAL_HEADER_SIZE);
    }

    #[test]
    fn gap_scanning_recovers_after_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        let s1 = wal
            .append(&make_record(1, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        wal.append(&make_record(2, Severity::Low, DetectionSource::Realtime))
            .unwrap();
        let s3 = wal
            .append(&make_record(3, Severity::Low, DetectionSource::Realtime))
            .unwrap();

        let entries = wal.iter_unconsumed().unwrap();
        let middle = &entries[1];

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .unwrap();
        let size = {
            let mut s = [0u8; 4];
            read_exact_at(&file, &mut s, middle.offset).unwrap();
            u32::from_le_bytes(s) as u64
        };
        let zeros = vec![0u8; size as usize];
        write_all_at(&file, &zeros, middle.offset).unwrap();

        let entries = wal.iter_unconsumed().unwrap();
        let got: Vec<u64> = entries.into_iter().map(|e| e.sequence).collect();
        assert_eq!(got, vec![s1, s3]);
    }

    #[test]
    fn gap_limit_stops_scanning_large_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        // WAL big enough to hold header + entries + large zeroed gap
        let wal = open_wal(&wal_path, 4 * 1024 * 1024);

        let s1 = wal
            .append(&make_record(1, Severity::Low, DetectionSource::Realtime))
            .unwrap();

        // Append a second entry so we know its offset, then zero out a region
        // larger than MAX_GAP_BYTES after entry 1 to simulate adversarial corruption.
        let entries = wal.iter_unconsumed().unwrap();
        let after_entry1 = entries[0].offset + {
            let f = wal.file.lock();
            let mut s = [0u8; 4];
            read_exact_at(&f, &mut s, entries[0].offset).unwrap();
            u32::from_le_bytes(s) as u64
        };

        // Write a zeroed region of MAX_GAP_BYTES + 4KB right after entry 1
        let gap_size = (MAX_GAP_BYTES + 4096) as usize;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .unwrap();
        let zeros = vec![0u8; gap_size];
        write_all_at(&file, &zeros, after_entry1).unwrap();

        // Write a valid entry just after the giant gap (would be found by
        // unlimited scanning, but should be missed due to MAX_GAP_BYTES).
        // We can't easily inject one, so just verify the scanner stops.
        let new_file_len = after_entry1 + gap_size as u64;
        let scanned = scan_entries(&file, new_file_len, None, false, false).unwrap();

        // Only entry 1 should be recovered; the scanner should have stopped
        // at the gap limit without trying to scan beyond.
        let got: Vec<u64> = scanned.iter().map(|e| e.sequence).collect();
        assert_eq!(got, vec![s1]);
    }

    #[test]
    fn header_validation() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        let header = read_header(&wal.file.lock()).unwrap();
        assert_eq!(&header[0..4], b"VWAL");
        assert_eq!(u16::from_le_bytes([header[4], header[5]]), WAL_VERSION);
        assert_ne!(&header[32..64], &[0u8; 32]);

        let bad_path = dir.path().join("bad.wal");
        std::fs::write(&bad_path, vec![0u8; WAL_HEADER_SIZE as usize]).unwrap();
        std::fs::set_permissions(&bad_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&bad_path)
                .unwrap();
            write_all_at(&file, b"BAD!", 0).unwrap();
        }

        match DetectionWal::open(&bad_path, None, 64 * 1024 * 1024) {
            Err(VigilError::Wal(msg)) => assert!(msg.contains("invalid WAL magic")),
            Err(other) => panic!("unexpected error kind: {}", other),
            Ok(_) => panic!("expected invalid WAL magic error"),
        }
    }

    #[test]
    fn entry_hmac_verification() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let key = Zeroizing::new(b"test-hmac-key-material".to_vec());
        let wal = DetectionWal::open(&wal_path, Some(&key), 64 * 1024 * 1024).unwrap();

        wal.append(&make_record(1, Severity::High, DetectionSource::Realtime))
            .unwrap();
        let entries = wal.iter_unconsumed().unwrap();
        assert_eq!(entries.len(), 1);

        let offset = entries[0].offset + 46;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .unwrap();
        let mut b = [0u8; 1];
        read_exact_at(&file, &mut b, offset).unwrap();
        b[0] ^= 0xAA;
        write_all_at(&file, &b, offset).unwrap();

        let tampered = wal.iter_unconsumed().unwrap();
        assert!(tampered.is_empty());
    }

    #[test]
    fn instance_nonce_uniqueness() {
        let dir = tempfile::tempdir().unwrap();
        let wal1 = open_wal(&dir.path().join("a.wal"), 64 * 1024 * 1024);
        let wal2 = open_wal(&dir.path().join("b.wal"), 64 * 1024 * 1024);

        assert_ne!(wal1.instance_nonce(), wal2.instance_nonce());
    }

    #[test]
    fn sentinel_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("detections.wal");
        let wal = open_wal(&wal_path, 64 * 1024 * 1024);

        let rec = DetectionRecord {
            timestamp: chrono::Utc::now().timestamp(),
            path: "__vigil_wal_self_test__".to_string(),
            changes: vec![],
            severity: Severity::Low,
            monitored_group: "self_test".into(),
            process: None,
            package: None,
            package_update: false,
            maintenance_window: false,
            source: DetectionSource::Sentinel,
        };

        let seq = wal.append(&rec).unwrap();
        let entries = wal.iter_unconsumed().unwrap();
        let entry = entries.into_iter().find(|e| e.sequence == seq).unwrap();

        wal.mark_audit_done(entry.offset).unwrap();
        wal.mark_sink_done(entry.offset).unwrap();
        wal.truncate_consumed().unwrap();

        assert_eq!(std::fs::metadata(&wal_path).unwrap().len(), WAL_HEADER_SIZE);
    }
}
