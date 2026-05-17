# `pkg/` — source-project packaging contract

This directory holds the source-project contract that
[`lousclues-labs/lousclues-pkg`](https://github.com/lousclues-labs/lousclues-pkg)
invokes to build `.deb` and `.rpm` artifacts at release time.

Validated by [`.github/workflows/pkg-build.yml`](../.github/workflows/pkg-build.yml)
on every PR that touches packaging-relevant files.

---

## Contract

`pkg/build.sh` reads three environment variables and emits exactly
one artifact per invocation:

| Env | Required | Meaning |
|-----|:--------:|---------|
| `DISTRO` | yes | one of `noble`, `jammy`, `bookworm`, `el9`, `fedora` |
| `VERSION` | yes | semver, no leading `v`; must match `Cargo.toml` |
| `OUTDIR` | yes | absolute path; exactly one `.deb` or `.rpm` lands here |

Exit codes:

- `0` — artifact emitted successfully.
- `1` — required env var missing.
- `2` — invalid input (unknown `DISTRO`, leading `v` in `VERSION`,
  relative `OUTDIR`, `VERSION` mismatch vs `Cargo.toml`).
- non-zero otherwise — build failure.

Distro → format mapping:

| `DISTRO` | Image | Output |
|---|---|---|
| `noble` | `ubuntu:24.04` | `.deb` |
| `jammy` | `ubuntu:22.04` | `.deb` |
| `bookworm` | `debian:12` | `.deb` |
| `el9` | `rockylinux:9` | `.rpm` |
| `fedora` | `fedora:latest` | `.rpm` |

---

## Optional knobs

These are honored when set; they have safe defaults otherwise.

| Env | Default | Purpose |
|-----|---------|---------|
| `SOURCE_DATE_EPOCH` | `git log -1 --pretty=%ct` | reproducible-build epoch; `pkg-build.yml` sets this explicitly and asserts that two passes with the same value produce byte-identical artifacts |
| `VIGIL_SKIP_DEPS` | unset | skip `apt-get`/`dnf` install of build deps (operator promises they are already present) |
| `VIGIL_SKIP_TOOLCHAIN` | unset | skip rustup install (operator promises a stable toolchain is on `PATH`) |
| `VIGIL_CARGO_TARGET_DIR` | `target/` | override `CARGO_TARGET_DIR` for cache reuse across invocations |

---

## Reproducibility

`pkg/build.sh` must be reproducible: two invocations with the same
`DISTRO`, `VERSION`, and `SOURCE_DATE_EPOCH` must produce
byte-identical artifacts (sha256 match). This is enforced by
`pkg-build.yml` (double-build + sha256 compare) and is the foundation
that makes [`docs/ATTEST.md`](../docs/ATTEST.md) signed attestations
meaningful.

---

## What gets shipped

The CI gate asserts the following installed layout. Every row is a
contract `pkg/build.sh` must satisfy:

- `/usr/bin/vigil` and `/usr/bin/vigild` (both executable).
- `/usr/bin/vigild` has `CAP_SYS_ADMIN`, either via file caps
  (`getcap` shows `cap_sys_admin+ep`) or via
  `AmbientCapabilities=CAP_SYS_ADMIN` in the systemd unit.
- `vigild.service` in `/lib/systemd/system/` (deb) or
  `/usr/lib/systemd/system/` (rpm); must pass
  `systemd-analyze verify`; must not reference dev-only paths
  (`/usr/local/bin/vigild`, `target/debug/`, `target/release/`).
- `/etc/vigil/vigil.toml.example` (mode `0644`, `root:root`).
- Man pages: `/usr/share/man/man8/vigild.8.gz`,
  `/usr/share/man/man1/vigil.1.gz`,
  `/usr/share/man/man5/vigil.toml.5.gz` (all gzipped, non-empty).
- Shell completions: `/usr/share/bash-completion/completions/vigil`,
  `/usr/share/zsh/site-functions/_vigil`,
  `/usr/share/fish/vendor_completions.d/vigil.fish`.
- Package-manager hooks (conditional on source-tree presence):
  - if `hooks/apt/<name>` exists, deb packages install
    `/etc/apt/apt.conf.d/<name>`.
  - if `hooks/dnf/` exists, rpm packages install
    `/etc/dnf/plugins/vigil.conf` and the matching python plugin.
- Docs: `/usr/share/doc/vigil/README.md`,
  `/usr/share/doc/vigil/changelog.gz`,
  `/usr/share/doc/vigil/copyright` (deb) or
  `/usr/share/doc/vigil/LICENSE` (rpm).
- `vigil --version` contains the resolved `Cargo.toml` version.
- `vigil --help`, `vigild --help`, and `timeout 10 vigil doctor`
  exit without segfault or hang.

---

## Status

`pkg/build.sh` is currently a fail-loud scaffold: every per-distro arm
exits non-zero with a `TODO` message. The CI gate is therefore red
until the per-distro arms are implemented to satisfy the contract
above. That is intentional — the gate forces the contract to be met
before the project can release through `lousclues-pkg`.
