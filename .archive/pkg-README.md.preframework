# `pkg/`: source-project packaging contract

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

- `0`: artifact emitted successfully.
- `1`: required env var missing.
- `2`: invalid input (unknown `DISTRO`, leading `v` in `VERSION`,
  relative `OUTDIR`, `VERSION` mismatch vs `Cargo.toml`).
- non-zero otherwise: build failure.

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
| `VIGIL_MANIFEST_COMMIT` | unset | first in the precedence chain for the `git_commit` field written into `<artifact>.manifest.json`; 40-char lowercase hex required, else `exit 2` |
| `SOURCE_SHA` | unset | second in the precedence chain; generic 40-hex commit set by the lousclues-pkg orchestrator so one env var applies across projects |

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

## Manifest sidecar

Each artifact is paired with a small `*.manifest.json` written next to
it in `OUTDIR`. This is the input
[`docs/ATTEST.md`](../docs/ATTEST.md) signs over:

```json
{
  "artifact": "vigil_1.12.0_amd64-noble.deb",
  "sha256": "<64 hex chars>",
  "size_bytes": 12345678,
  "version": "1.12.0",
  "distro": "noble",
  "source_date_epoch": 1700000000,
  "git_commit": "<40 hex chars>"
}
```

The manifest format is deliberately tiny and stable. Any field
addition is a breaking change for `lousclues-pkg`'s attestation step.

`git_commit` precedence (first non-empty wins):

1. `VIGIL_MANIFEST_COMMIT` -- project-prefixed explicit override.
2. `SOURCE_SHA` -- generic, set by the lousclues-pkg orchestrator.
3. `git rev-parse HEAD` in the source tree.
4. `"unknown"` -- only when `CI` is unset. In CI the script
   `exit 1`s instead, so attestation never silently loses the
   source commit.

Non-empty values in steps 1, 2, and 3 are validated as 40-char
lowercase hex; malformed input is `exit 2`.

---

## File capabilities

`/usr/bin/vigild` needs `cap_sys_admin` (fanotify) and
`cap_dac_read_search` (read paths regardless of DAC). These are
granted at install time by the package's `postinst` scriptlet:

```sh
setcap cap_sys_admin,cap_dac_read_search+ep /usr/bin/vigild
```

`AmbientCapabilities=` is deliberately *not* set in the systemd unit:
file caps are narrower (they don't propagate to children, and they
fail loudly if `setcap` is missing). The unit's
`CapabilityBoundingSet=` remains as the upper bound the process may
ever hold.

The CI layout-check accepts either file caps *or*
`AmbientCapabilities=` (so the unit is back-portable), but the build
script ships with file caps.

---

## Local invocation

Reproduce one matrix entry on a developer laptop. Docker keeps the
build hermetic; `$PWD` is mounted read-only into the container so a
stray write under `target/` can't pollute the host tree.

```sh
# noble (.deb). Swap the image + DISTRO for any other matrix entry.
mkdir -p ./out
docker run --rm \
  -v "$PWD":/src:ro \
  -v "$PWD/out":/out \
  -w /work \
  -e DISTRO=noble \
  -e VERSION="$(awk -F'\"' '/^version[[:space:]]*=/{print $2; exit}' Cargo.toml)" \
  -e OUTDIR=/out \
  -e SOURCE_DATE_EPOCH=1700000000 \
  ubuntu:24.04 \
  bash -c 'cp -a /src /work && bash /work/pkg/build.sh'

ls out/                    # vigil_<v>_amd64-noble.deb + .manifest.json
sha256sum out/*.deb
jq . out/*.deb.manifest.json
```

Pinning `SOURCE_DATE_EPOCH` to a constant makes the artifact
byte-reproducible across hosts. Drop the env var to let the script
fall back to the last git commit time.

Skip-knobs (`VIGIL_SKIP_DEPS=1`, `VIGIL_SKIP_TOOLCHAIN=1`) let an
already-prepared container shave the apt/dnf and rustup steps.

---

## CI gate cross-reference

[`.github/workflows/pkg-build.yml`](../.github/workflows/pkg-build.yml)
is the merge-blocking validator. Three layers, fastest first:

1. **lint** -- `shellcheck -x` + `bash -n` on `pkg/build.sh`,
   `scripts/fix-debian-deps.sh`, `setup.sh`, and any
   `hooks/**/*.sh` / `contrib/**/*.sh` present.
2. **input-tests** -- runs `pkg/build.sh` with deliberately bad
   inputs and pins the exit-code contract (`1` for missing required
   env, `2` for invalid value).
3. **build** -- per-distro container build. Each matrix entry runs
   `pkg/build.sh` twice, sha256-compares the two artifacts
   (reproducibility), then installs the package and asserts the
   installed layout: binaries, file caps, systemd unit (incl.
   `systemd-analyze verify`), config file mode + ownership, man
   pages, completions, hooks, docs, runtime smoke
   (`vigil --version`, `--help`, `doctor`, `vigild --help`).
   A `verify manifest sidecar` step parses the `*.manifest.json`
   with `jq` and asserts sha256/version/distro match the artifact
   and `git_commit` is 40-char hex (never `"unknown"` in CI).

Aggregate gate: `pkg-success`. That single check name is what branch
protection requires.

---

## Differences from sibling project (shroud)

`lousclues-labs/shroud` has the same `pkg/build.sh` shape and the
same `pkg-build.yml` shape. Vigil and shroud diverge on the
following points by design. Anything outside this list is debt.

1. **Privilege model.** Vigil uses file caps + `setcap` in
   `postinst`. Shroud uses sudoers `0440` + `visudo`.
2. **Binary count.** Vigil ships two binaries (`vigil` + `vigild`).
   Shroud ships one (`shroud`).
3. **Generated artifacts.** Vigil renders man pages + shell
   completions from the freshly built binary at staging time
   (`vigil man`, `vigil completions`). Shroud ships none.
4. **Package-manager hooks.** Vigil ships `hooks/apt/` and
   `hooks/dnf/` for transaction-window baseline refresh. Shroud
   ships no hooks.
5. **Desktop integration.** Vigil ships none. The daemon is
   silent-by-default. Shroud ships a `.desktop` file, a polkit
   rule, and an `update-desktop-database` postinst trigger.
6. **License tag.** Vigil: `GPL-3.0-only`. Shroud: `GPL-3.0-or-later`.
7. **`fix-debian-deps.sh`.** Vigil-only. Shroud's deb dep graph
   doesn't trigger the libsystemd0 skew on jammy/bookworm container
   images.
8. **Runtime deps.** Divergent by construction. Vigil pulls
   `libcap2-bin` + `procps`. Shroud pulls its own set.

Any divergence outside this list is debt. Fix it or document it here.

---

## Status

Implemented. The per-distro arms run end-to-end in CI for all five
target distros; the workflow's installed-layout check passes on every
green run. Local dry-runs against a shim `fpm` cleanly produce the
expected staging tree.

If the gate goes red, suspect one of:

- a new file added to the source tree that the layout-check expects
  to be packaged (update `stage_assets` in `pkg/build.sh`);
- a missing system dependency on a fresh distro image (update
  `install_{deb,rpm}_deps`);
- an `fpm` argument that gained a default in a new release (pin
  `fpm` in `ensure_toolchain` if drift becomes painful);
- a reproducibility regression (the gate runs two passes and compares
  sha256; diff the `--inspect` outputs of the failing pair from the
  uploaded `nonrepro-*` artifact).

---

*The pipeline that produces the artifact is the contract. Keep them honest.*
