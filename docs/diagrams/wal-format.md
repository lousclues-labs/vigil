# WAL Format

The on-disk byte layout of the detection WAL (Write-Ahead
Log). This is a stability commitment — the format cannot
change without breaking compatibility, so the diagram will
not change either.

The WAL is opened from `src/wal/mod.rs::DetectionWal::open`.

```
╭─────────────────── WAL File ───────────────────────╮
│                                                    │
│  ╭─────────────── Header (64 bytes) ─────────────╮ │
│  │                                               │ │
│  │  Offset  Size  Field                          │ │
│  │  ──────  ────  ─────────────────────────────  │ │
│  │   0       4    magic          b"VWAL"         │ │
│  │   4       2    version        1 (u16 LE)      │ │
│  │   6      10    reserved       (zero-filled)   │ │
│  │  16      16    hmac_fingerprint               │ │
│  │                  BLAKE3(key)[0..16]            │ │
│  │                  or [0×16] if no HMAC          │ │
│  │  32      32    instance_nonce                  │ │
│  │                  /dev/urandom at creation      │ │
│  │                  binds entries to this file    │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭─────────────── Entry N ───────────────────────╮ │
│  │                                               │ │
│  │  Offset  Size  Field                          │ │
│  │  ──────  ────  ─────────────────────────────  │ │
│  │   +0      4    entry_size     (u32 LE)        │ │
│  │                  total bytes including this    │ │
│  │   +4      8    sequence       (u64 LE)        │ │
│  │                  monotonic, never reused       │ │
│  │  +12      2    flags          (u16 LE)        │ │
│  │                  bit 0: FLAG_AUDIT_DONE       │ │
│  │                  bit 1: FLAG_SINK_DONE        │ │
│  │  +14     32    hmac           (32 bytes)      │ │
│  │                  HMAC-SHA256(key,             │ │
│  │                    nonce ‖ sequence ‖ payload)│ │
│  │                  or [0×32] if no HMAC key     │ │
│  │  +46      V    payload        (V bytes)       │ │
│  │                  JSON-encoded DetectionRecord  │ │
│  │  +46+V    4    crc32          (u32 LE)        │ │
│  │                  CRC32C of bytes [+0..+46+V)  │ │
│  │                  covers size+seq+flags+hmac   │ │
│  │                    +payload (NOT the CRC)     │ │
│  │                                               │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
│  ╭─────────────── Entry N+1 ─────────────────────╮ │
│  │  ...                                          │ │
│  ╰───────────────────────────────────────────────╯ │
│                                                    │
╰────────────────────────────────────────────────────╯

 Constants:
   WAL_HEADER_SIZE  = 64 bytes
   MIN_ENTRY_SIZE   = 50 bytes (4+8+2+32+0+4)
   MAX_ENTRY_SIZE   = 1,048,576 bytes (1 MB)
   MAX_GAP_BYTES    = 65,536 bytes (gap scan limit)
```

## Walkthrough

**Header.** Written once at file creation. The magic bytes
identify the file as a vigil WAL. The version enables
future format evolution. The HMAC fingerprint is the first
16 bytes of BLAKE3(key), binding the WAL to a specific
HMAC key; opening with the wrong key is rejected at
startup. The instance nonce is 32 random bytes from
`/dev/urandom`, unique per WAL file; it is mixed into
every entry HMAC to prevent cross-file replay attacks.

**Entry framing.** Entries are variable-length, not
aligned. The entry_size field enables forward scanning.
The sequence number is monotonically increasing and never
reused, even after truncation. Flags track per-consumer
consumption (bit 0 for audit writer, bit 1 for sink
runner). The HMAC signs `nonce ‖ sequence ‖ payload` with
HMAC-SHA256, preventing tampering and replay. The CRC32C
at the tail covers everything except itself, detecting
torn writes on crash recovery.

**Crash recovery.** On reopen, the WAL scans forward from
the header. Each entry's CRC is verified; entries past the
last valid CRC are discarded (torn write at tail). The gap
scanner can skip up to `MAX_GAP_BYTES` of invalid data to
recover entries after a corrupted region, but will not
scan indefinitely (preventing adversarial DoS from zeroed
regions).

**HMAC enforcement.** If the header's fingerprint is
non-zero (WAL was created with HMAC), opening without a
key is rejected (VIGIL-VULN-067). This prevents security
downgrade by simply removing the key file.

This diagram shows the on-disk byte layout. It does NOT
show the append path (locking, sync modes), the gap
scanning algorithm (see code comments in
`src/wal/mod.rs::scan_entries`), or the truncation
mechanics (see `DetectionWal::truncate_consumed`).

## Related diagrams

- [wal-consumers.md](wal-consumers.md) — how flag bits
  track consumption
- [audit-chain.md](audit-chain.md) — what happens after
  entries reach the audit DB
