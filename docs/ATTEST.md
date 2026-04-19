# Attestation

Portable, signed, self-contained evidence of Vigil baseline and audit state.

---

## Purpose

`vigil attest` produces attestations (`.vatt`) that let an operator prove what
Vigil's baseline and audit chain looked like at a specific moment.

Attestations are evidence artifacts. They are not for recovery.

- They do not modify monitored files.
- They do not rebuild host state.
- They do not depend on daemon availability at verification time.

---

## Threat Model Addition

This feature addresses a specific evidentiary problem:

> The host can no longer be trusted as a witness to its own past.

Attestations are designed to survive independent of the source host (seizure,
coerced modification, silent substitution, later repudiation) and remain
verifiable using only:

- a Vigil binary,
- the `.vatt` file,
- and the attestation signing key (for HMAC-BLAKE3 signatures).

No daemon, baseline DB, network, or host-local runtime state is required.

---

## Principle Alignment

`vigil attest` aligns with [PRINCIPLES.md](PRINCIPLES.md):

- I (watch, don't act): read-only against baseline/audit DBs during create;
  verification is read-only against the file.
- II (silence is default): operator-invoked command only; no background scheduling.
- III (determinism): deterministic CBOR format + `--deterministic-time` for test reproducibility.
- IV (structure over behavior): attestation captures structural facts (hashes,
  metadata, chain links, config text), no heuristics.
- V (clear/actionable): verify reports explicit pass/fail checks.
- VI (filesystem is truth): attestations are plain files.
- VIII (stands alone): verification works offline with binary + file (+ key).
- IX (no config required): sane defaults for scope, key path search, output naming.
- X (fail open, fail loud): verification failures are explicit and non-ambiguous.
- XI (complexity): compact implementation, no network stack, no compression,
  no extra crypto protocol layers.
- XII (baseline is sacred): attestation externalizes baseline declaration over time.
- XIII (audit never lies): attestation anchors chain head and can detect forks.
- XIV (no network): zero network I/O.
- XV (operator decides): all creation/verification actions are explicit CLI actions.

---

## Scopes

`vigil attest create --scope <scope>` supports three scopes:

- `full`: baseline entries + audit entries + config snapshot + watch groups.
- `baseline-only`: baseline entries + config snapshot + watch groups.
- `head-only`: header-only attestation anchored to current counts and chain head.

When to use:

- `full`: strongest portable forensic record.
- `baseline-only`: prove baseline state without carrying full audit history.
- `head-only`: small receipt-like anchor for chain and baseline counters.

---

## Workflows

### Periodic golden state for workstation

```bash
sudo vigil setup attest
vigil attest create --scope full
vigil attest list
```

Store `.vatt` files off-host (e.g. removable media, evidence vault).

### Evidence before high-risk travel

```bash
vigil check --full
vigil audit verify
vigil attest create --scope full --out pre-travel.vatt
```

### Prove baseline existed before a disputed event

```bash
vigil attest verify pre-incident.vatt --key-path /secure/attest.key
```

### Compare two systems' declared state

```bash
vigil attest diff host-a.vatt --against host-b.vatt
```

---

## Key Management

Attestation signing key is separate from `hmac.key`.

Why separate keys:

- audit HMAC key signs local live audit records,
- attestation key signs portable artifacts that leave the host,
- compromise domains are independent,
- operators can rotate independently.

Generate key:

```bash
sudo vigil setup attest
```

Defaults:

- key path: `/etc/vigil/attest.key`
- file mode: `0600`
- format: `0x01 || 32 random bytes`

Key ID derivation:

- first 8 bytes of `BLAKE3("vigil-attest-key-id-v1" || key)`

Rotation guidance:

1. generate new attestation key,
2. archive old key with prior attestation set,
3. keep key lineage metadata with evidence package,
4. verify fresh artifacts with new key.

---

## CLI Reference

### `vigil attest create`

```bash
vigil attest create [--scope full|baseline-only|head-only] [--out PATH] [--key-path PATH]
```

Flags:

- `--scope`: attestation scope (default: `full`)
- `--out`: output file path (default: auto-generated `.vatt` path)
- `--key-path`: explicit signing key path
- `--deterministic-time <RFC3339>`: hidden test-only determinism flag

### `vigil attest verify`

```bash
vigil attest verify <attestation-file> [--key-path PATH]
```

Verifies format, content hash, signature, and embedded chain links.

### `vigil attest diff`

```bash
vigil attest diff <attestation-file> [--against current|<other-attestation-file>]
```

Reports baseline structural differences and audit chain relationship.

### `vigil attest show`

```bash
vigil attest show <attestation-file> [--verbose]
```

Shows header/footer and optional full payload summaries.

### `vigil attest list`

```bash
vigil attest list [--dir PATH]
```

Lists `.vatt` files and concise metadata summary.

### `vigil setup attest`

```bash
vigil setup attest [--key-path PATH] [--force]
```

Creates attestation signing key file.

### Exit Codes (`attest verify`)

- `0`: valid
- `1`: invalid attestation (verification failed)
- `2`: usage error (invalid CLI usage/scope)
- `3`: I/O error (unreadable file, etc.)

---

## File Format Specification (`.vatt`)

Encoding: CBOR via deterministic serialization rules.

Top-level structure:

- `header`
- `body`
- `footer`

`header` includes:

- magic `"VIGIL-ATTEST"` (12 bytes)
- `format_version` (`u16`, current `1`)
- creation timestamps (wall + monotonic)
- host identity (hash + hint)
- baseline/audit counters
- audit chain head hash
- creator Vigil version
- scope

`body` includes (scope-dependent):

- baseline entries
- audit entries
- config snapshot
- watch groups

`footer` includes:

- content hash (`BLAKE3` over deterministic CBOR of `header||body`)
- signature scheme
- signature bytes
- signing key ID

Version policy:

- verifier accepts known/supported versions,
- unknown higher format versions are rejected clearly,
- wire structs are explicit and versioned to avoid DB/serde ambiguity.

Forward compatibility rules:

- do not repurpose existing field meanings,
- introduce additive fields/version bumps intentionally,
- keep verifier checks strict and explicit.
