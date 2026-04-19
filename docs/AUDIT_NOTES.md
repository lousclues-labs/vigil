# Documentation Audit Notes (v0.41.0)

Working notes for the v0.42.0 documentation audit. Delete before merge.

---

## Per-File Status

| File | Lines | Last Update | Verdict | Notes |
|------|-------|-------------|---------|-------|
| `README.md` | 275 | 2026-04-18 | current | version badge correct (0.41.0), doc table complete, `vigil attest` surfaced in capabilities |
| `CHANGELOG.md` | 3450 | 2026-04-18 | needs refresh | em-dashes throughout (v0.34+), needs sweep |
| `docs/README.md` | 70 | 2026-04-18 | current | index covers all docs |
| `docs/CLI.md` | 1048 | 2026-04-18 | current | all v0.41.0 commands documented, JSON schema examples present |
| `docs/CONFIGURATION.md` | 298 | 2026-04-18 | partial drift | missing `[monitor]` section (event_loss_alert_threshold), missing `[maintenance]` section (max_window_seconds), self_check_interval present but monitor/maintenance sections not in option reference |
| `docs/ARCHITECTURE.md` | 499 | 2026-04-18 | partial drift | em-dashes, missing src/attest/ from module tree, missing new commands/ files (attest.rs, explain.rs, inspect.rs, test_alert.rs, why_silent.rs), missing display/term.rs unsafe |
| `docs/SECURITY.md` | 372 | 2026-04-18 | partial drift | missing ciborium + constant_time_eq from dependency table, missing display/term.rs from unsafe table, constant_time_eq MSRV pin not documented |
| `docs/ATTEST.md` | 257 | 2026-04-18 | needs refresh | missing CBOR determinism guarantee (RFC 8949 section 4.2), missing offline verification worked example with copy commands |
| `docs/FORENSICS.md` | 56 | 2026-04-18 | stale | essentially a stub, missing offline mode description, air-gapped workflow, JSON output |
| `docs/THREAT_MODEL.md` | 238 | 2026-04-18 | current | attestation threat model present, closed-set documented, fanotify overflow documented |
| `docs/RESILIENCE.md` | 281 | 2026-04-18 | current | comprehensive failure modes, WAL failures, version upgrade recovery |
| `docs/VULNERABILITIES.md` | 843 | 2026-04-18 | current | VIGIL-VULN-001 through VIGIL-VULN-074 all present |
| `docs/PRINCIPLES.md` | 282 | 2026-04-18 | needs refresh | 18+ em-dashes to replace |
| `docs/TROUBLESHOOTING.md` | 331 | 2026-04-18 | current | update-stuck section present, quick diagnostic commands table present |
| `docs/TESTING.md` | 274 | 2026-04-18 | partial drift | fuzz target list shows 8 targets (missing fuzz_attest_file, fuzz_attest_verify) |
| `docs/DEVELOPMENT.md` | 270 | 2026-04-18 | partial drift | fuzz target list shows 7, test tree missing 4 files |
| `docs/INSTALL.md` | 246 | 2026-04-18 | current | systemd unit names correct, paths correct |
| `docs/FAQ.md` | 122 | 2026-04-18 | current | no drift found |
| `docs/RELEASING.md` | 156 | 2026-04-18 | current | checklist matches release.yml |
| `docs/MINIMUM_VIABLE.md` | 164 | 2026-04-18 | current | closed-set, inspect, explain, why-silent all documented |

---

## Shipped Features Since v0.34.0 -- Coverage Gaps

| Feature | Version | Doc Coverage | Gap |
|---------|---------|-------------|-----|
| `vigil attest` (.vatt) | v0.41.0 | docs/ATTEST.md, docs/CLI.md | missing CBOR determinism detail, missing offline worked example |
| `vigil inspect` | v0.41.0 | docs/FORENSICS.md, docs/CLI.md | FORENSICS.md is a stub (56 lines) |
| `vigil diff` | v0.31.0 | docs/CLI.md | covered |
| `vigil check --accept` | v0.31.0 | docs/CLI.md | covered with all flags |
| `vigil setup hmac` | v0.32.0 | docs/CLI.md | covered |
| `vigil setup socket` | v0.32.0 | docs/CLI.md | covered |
| `vigil update` UX | v0.36.0+ | docs/CLI.md | JSON schema samples present, env vars documented |
| Control socket peer-UID enforcement | v0.34.0 | docs/SECURITY.md | covered |
| fanotify queue overflow recovery | v0.34.0 | docs/RESILIENCE.md, docs/THREAT_MODEL.md | covered |
| mountinfo octal decoding | v0.34.0 | docs/VULNERABILITIES.md | covered |
| `vigil explain` | v0.41.0 | docs/CLI.md | covered |
| `vigil why-silent` | v0.41.0 | docs/CLI.md | covered |
| `vigil test alert` | v0.41.0 | docs/CLI.md | covered |
| closed-set watches | v0.41.0 | docs/CONFIGURATION.md, docs/THREAT_MODEL.md | covered |
| self_check_interval | v0.41.0 | docs/CONFIGURATION.md | covered in watch modes section, missing from option reference |
| `[monitor]` config section | v0.35.0 | docs/CONFIGURATION.md | missing from option reference |
| `[maintenance]` config section | v0.35.0 | docs/CONFIGURATION.md | missing from option reference |
| ciborium dependency | v0.41.0 | docs/SECURITY.md | missing from dependency table |
| constant_time_eq dependency | v0.34.0 | docs/SECURITY.md | missing from dependency table, MSRV pin not documented |
| display/term.rs unsafe | v0.31.0 | docs/SECURITY.md | missing from unsafe table |
| fuzz_attest_file target | v0.41.0 | docs/TESTING.md | missing |
| fuzz_attest_verify target | v0.41.0 | docs/TESTING.md | missing |

---

## Cross-Cutting Issues

1. **Em-dashes (U+2014):** found in PRINCIPLES.md (~18), ARCHITECTURE.md (~10+), CHANGELOG.md (many)
2. **Forbidden words:** TBD (sweep after edits)
3. **Version strings:** CLI.md version output example shows "0.19.0"
4. **Internal links:** all resolve (verified)

---

## Priority Order

1. Em-dash sweep (PRINCIPLES.md, ARCHITECTURE.md, CHANGELOG.md)
2. FORENSICS.md expansion (biggest gap)
3. SECURITY.md drift fixes (dependency table, unsafe table, constant_time_eq)
4. CONFIGURATION.md missing sections
5. TESTING.md and DEVELOPMENT.md fuzz target updates
6. ATTEST.md detail additions
7. ARCHITECTURE.md module tree updates
8. CLI.md version string fix
