# Audit HMAC Format (VIGIL-VULN-076)

This document describes the HMAC encoding formats used to sign audit chain entries. It serves as a stable reference for external auditors verifying chains independently.

## v1: Legacy Pipe-Delimited Encoding

**Status:** Deprecated for writes. Kept for verification of existing entries.

The v1 format constructs HMAC input as a pipe-delimited string:

```
{timestamp}|{path}|{change_type}|{severity}|{old_hash}|{new_hash}|{previous_chain_hash}
```

### Known Weakness

Linux paths may contain `|`. Two distinct logical inputs can produce identical HMAC input bytes:

| Input A | Input B |
|---------|---------|
| path=`/etc/foo\|bar`, change=`modified` | path=`/etc/foo`, change=`bar\|modified` |

Both produce: `1700000000|/etc/foo|bar|modified|high|||genesis`

This breaks the tamper-evidence guarantee of the audit chain for paths containing the delimiter.

### Identification

Entries with `encoding_version = 1` (or NULL/missing column) use this format.

---

## v2: Canonical CBOR Encoding

**Status:** Active. All new entries use this format.

The v2 format encodes HMAC input as a deterministic CBOR map (RFC 8949 §4.2).

### CBOR Structure

```
Map(7) {
  "change" → Text(change_type),
  "new"    → Text(new_hash) | Null,
  "old"    → Text(old_hash) | Null,
  "path"   → Bytes(path_bytes),
  "prev"   → Text(previous_chain_hash),
  "sev"    → Text(severity),
  "ts"     → Integer(timestamp)
}
```

### Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| **CBOR map** (not array) | Self-describing; forward-compatible with new fields |
| **Lexicographic key order** | Deterministic per RFC 8949 §4.2.1 |
| **Path as byte string** | Preserves non-UTF-8 path bytes (rare but legal on Linux) |
| **Optional fields use `Null`** | Not omitted; ensures field count is always 7 |
| **Definite-length encoding** | ciborium default; required by RFC 8949 §4.2 |

### Identification

Entries with `encoding_version = 2` use this format.

### Worked Example

**Input fields:**
- timestamp: `1700000000`
- path: `/etc/passwd`
- change_type: `content_modified`
- severity: `high`
- old_hash: `aabbccdd`
- new_hash: `eeff0011`
- previous_chain_hash: `deadbeef01234567`

**CBOR bytes (hex):**
```
a7                                      # map(7)
  66 6368616e6765                        # text(6) "change"
  70 636f6e74656e745f6d6f646966696564    # text(16) "content_modified"
  63 6e6577                              # text(3) "new"
  68 6565666630303131                    # text(8) "eeff0011"
  63 6f6c64                              # text(3) "old"
  68 6161626263636464                    # text(8) "aabbccdd"
  64 70617468                            # text(4) "path"
  4b 2f6574632f706173737764              # bytes(11) "/etc/passwd"
  64 70726576                            # text(4) "prev"
  70 6465616462656566303132333435363     # text(16) "deadbeef01234567"
  63 736576                              # text(3) "sev"
  64 68696768                            # text(4) "high"
  62 7473                                # text(2) "ts"
  1a 6554f800                            # unsigned(1700000000)
```

**HMAC:** `HMAC-SHA256(key, cbor_bytes)`

---

## Mixed-Version Verification Policy

- `verify_chain_detail()` reads `encoding_version` per row
- v1 entries → `build_audit_hmac_data()` (pipe-delimited)
- v2 entries → `build_audit_hmac_data_v2()` (canonical CBOR)
- Mixed v1+v2 chains verify correctly (tested by `audit_chain_v1_v2_mixed.rs`)
- The v1 verification path is kept **forever** — no auto-rewrite of v1 entries

## Schema

```sql
ALTER TABLE audit_log ADD COLUMN encoding_version INTEGER NOT NULL DEFAULT 1;
```

Existing rows default to `1`. New rows are written with `2`.

---

## Out-of-band columns (not in HMAC input)

Some columns are persisted alongside an audit row but are **not** part of
either the chain-hash input or the HMAC input. They are forensic
enrichment, not integrity envelope.

### `disambiguation` (added in 1.8.1)

JSON-encoded result of `vigil::hash::disambiguate_via_cache_drop`. One of:
`page_cache_only`, `disk_modification`, `active_modification`,
`inconclusive`, or `match`. NULL when disambiguation was not run.

This column is **excluded from the chain-hash input** for two reasons:

1. **Backward compatibility.** Audit chains written by 1.7.x and earlier
   continue to verify byte-for-byte against 1.8.1+ verifiers.
2. **Separation of concerns.** Disambiguation is a forensic refinement
   computed *after* the integrity event has already been recorded. The
   chain hash binds the event itself (path, change type, hashes,
   severity, timestamp); the classification of *why* the cache and disk
   disagreed is metadata that an operator may inspect, redact, or
   recompute without invalidating the chain.

If a deployment requires the disambiguation result to be tamper-evident,
the recommended path is to enable HMAC signing (which already covers the
chain hash) and treat the chain hash as the authoritative record of the
event; the `disambiguation` column then serves as advisory context.
