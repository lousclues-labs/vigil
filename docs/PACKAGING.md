# Packaging Vigil with `lousclues-pkg`

> **Audience:** maintainers cutting a release, contributors editing
> anything under `pkg/`, `systemd/`, `hooks/`, `config/`, or
> `contrib/`, and operators trying to reason about where the
> official `.deb` / `.rpm` artifacts came from and what guarantees
> they carry.
>
> **Companion docs.** This file is the narrative; the technical
> contract lives in [`../pkg/README.md`](../pkg/README.md). The
> reproducibility and signed-attestation story lives in
> [ATTEST.md](ATTEST.md). The release-cut runbook lives in
> [RELEASING.md](RELEASING.md). Operator-facing install steps
> (manual source builds) live in [INSTALL.md](INSTALL.md).

---

## What is lousclues-pkg?

[`lousclues-labs/lousclues-pkg`](https://github.com/lousclues-labs/lousclues-pkg)
is the **publishing pipeline** shared by every binary project in
the lousclues-labs org. It is a separate repository with one job:
take a tagged release of a source project and produce signed,
reproducible `.deb` and `.rpm` artifacts for the supported distro
matrix, then publish them to the org's apt and dnf repositories.

The split is deliberate. Source projects (this repo) own the
*content* of a package: what binaries ship, where they install, what
caps they need, what systemd units and hooks they bring with them.
The publishing pipeline (lousclues-pkg) owns the *plumbing*: GPG
signing, repository indexing, mirroring, attestation publishing, and
the per-distro container fleet that runs the actual `fpm`
invocation.

This document covers the **source-project half** of that split — the
contract this repo exposes to lousclues-pkg, the CI gate that
guarantees the contract holds, and the lessons banked from the
post-spec hardening pass that established the current shape of the
system.

---

## The five-piece source-project contract

Everything lousclues-pkg needs from this repo is encoded in these
files. If you understand what each one is responsible for, you
understand the packaging system.

### 1. `pkg/build.sh` — the build entry point

A POSIX bash script that reads `DISTRO`, `VERSION`, `OUTDIR` from
the environment and emits **exactly one** `.deb` or `.rpm` into
`OUTDIR`. lousclues-pkg invokes it once per (release × distro)
combination inside the matching distro container.

The script is opinionated and minimal. It does:

- per-distro build-dep install (`apt-get` / `dnf`), gated by
  `VIGIL_SKIP_DEPS` for cache-warm runs;
- rustup + fpm bootstrap, gated by `VIGIL_SKIP_TOOLCHAIN`;
- two-binary `cargo build --release --locked --frozen` for the
  `vigil` CLI and the `vigild` daemon;
- staging tree assembly under `target/pkg/stage/`: binaries,
  systemd units, config example, generated shell completions,
  generated man pages, apt/dnf hooks (conditional on source-tree
  presence), and the standard docs set;
- `fpm` invocation with pinned metadata (name, version, license,
  url, vendor, maintainer, depends, file-attrs, postinst);
- emission of a `*.manifest.json` sidecar next to the artifact for
  the attestation step.

What it deliberately does **not** do: sign anything, push anything,
build for more than one distro per invocation, or read any state
from outside the source tree + the three required env vars.

See [`../pkg/README.md`](../pkg/README.md) for the full env-var
table, exit-code contract, and installed-layout invariants.

### 2. `.github/workflows/pkg-build.yml` — the merge-blocking gate

A three-layer workflow that proves `pkg/build.sh` honours its
contract on every PR that touches packaging-relevant files. The
aggregate check `pkg-success` is the single required status for
branch protection on `main`.

- **Layer 1 — lint.** `shellcheck pkg/build.sh`, `bash -n
  pkg/build.sh`, `systemd-analyze verify systemd/*.service`,
  `apt-get check`-style parse of `hooks/apt/99vigil` against a
  scratch `/etc/apt/apt.conf.d/`. Cheap, runs on every PR.
- **Layer 2 — negative-input tests.** Run `pkg/build.sh` with
  missing env vars, leading-`v` `VERSION`, relative `OUTDIR`,
  unknown `DISTRO`, mismatched `VERSION` vs `Cargo.toml`; assert
  each fails with the documented exit code and a meaningful
  message on stderr.
- **Layer 3 — per-distro container build.** Matrix over noble,
  jammy, bookworm, el9, fedora. Inside each container: build
  twice with the same `SOURCE_DATE_EPOCH`, sha256-compare for
  reproducibility, install the artifact via `dpkg -i
  --force-depends` / `rpm -ivh --nodeps`, then assert the full
  installed-layout invariant set (binaries, caps, unit,
  config, man pages, completions, hooks, docs, smoke-test
  `vigil --version` / `vigil --help` / `vigild --help` /
  `timeout 10 vigil doctor`).

Path-filtered so the matrix doesn't run on docs-only PRs:
`pkg/`, `systemd/`, `config/`, `contrib/`, `hooks/`, top-level
`Cargo.toml` / `Cargo.lock`, and the workflow itself.

### 3. `systemd/vigild.service` — the unit lousclues-pkg ships

The daemon unit. The packaging-relevant invariants are:

- must pass `systemd-analyze verify` on every supported distro;
- must not reference dev-only paths (`/usr/local/bin/vigild`,
  `target/debug/`, `target/release/`);
- must reference only post-usrmerge canonical paths
  (`/usr/bin/<tool>`, not `/bin/<tool>` — see the kill(1) lesson
  below);
- must declare `CapabilityBoundingSet=CAP_SYS_ADMIN
  CAP_DAC_READ_SEARCH` as the upper bound the daemon may ever
  hold;
- must declare `AmbientCapabilities=CAP_SYS_ADMIN
  CAP_DAC_READ_SEARCH` as the fallback when file caps had to be
  reverted at install time (see the `AT_SECURE=1` lesson below).

The CI layout-check accepts **either** file caps via `setcap` in
postinst **or** `AmbientCapabilities=` in the unit. The packages
ship with both — file caps as the preferred posture, ambient as
the safety net.

### 4. `hooks/{apt,dnf,pacman}/` — the package-manager integration

Hooks let vigil enter a *maintenance window* during package
transactions so the file changes apt/dnf/pacman make do not trip
the integrity baseline.

Each backend has a different file layout dictated by what its
configuration parser allows:

| Backend | Files | Why |
|---|---|---|
| `pacman` | `vigil-pre.hook`, `vigil-post.hook` | `pacman.hook(5)` allows multi-line `Exec=` directly; one self-contained file per phase |
| `apt` | `99vigil` + `apt-pre.sh` + `apt-post.sh` | `apt.conf(5)` has no escape for `"` inside `"..."`; multi-line shell with quoted log messages must live in separate scripts referenced by path |
| `dnf` | `vigil.conf` + `vigil.py` | DNF4 plugin ABI requires a python plugin file plus a `.conf` toggle; DNF5 (Fedora 41+) uses a different ABI and is a separate port |

All three backends honour the same operational contract from
[PRINCIPLES.md](PRINCIPLES.md) ("Hooks Must Never Block, but Must
Always Be Loud"): exit 0 if vigil is missing or the refresh fails
(transaction must always complete), but escalate critical failure
modes via `logger -p daemon.err` (operator alarm) and
`notify-send` when available. Tests in
`tests/hook_failure_isolation_tests.rs` enforce this contract for
each script.

### 5. The `*.manifest.json` sidecar — the attestation seed

Each artifact ships with a small JSON sidecar in `OUTDIR`:

```json
{
  "artifact": "vigil_1.11.5_amd64-noble.deb",
  "sha256": "<64 hex chars>",
  "size_bytes": 12345678,
  "version": "1.11.5",
  "distro": "noble",
  "source_date_epoch": 1700000000,
  "git_commit": "<40 hex chars>"
}
```

This is the input lousclues-pkg signs over in its attestation
step. The format is deliberately tiny and stable; any field
addition is a breaking change for the publishing pipeline. See
[ATTEST.md](ATTEST.md) for the full signing flow.

---

## End-to-end release flow

```
┌─────────────────────────────────────────────────────────────────┐
│ source repo (this repo, lousclues-labs/vigil)                  │
│                                                                 │
│  developer ──► PR touches pkg/ or systemd/ ──►                 │
│                                                                 │
│   .github/workflows/pkg-build.yml runs all three layers ──►    │
│   pkg-success status = green ──►                                │
│   maintainer merges ──►                                         │
│                                                                 │
│   maintainer runs `git tag v1.11.5 && git push --tags` ──►     │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ publishing repo (lousclues-labs/lousclues-pkg)                  │
│                                                                 │
│  tag webhook ──►                                                │
│  for each distro in matrix:                                     │
│    git clone lousclues-labs/vigil at v1.11.5 ──►               │
│    docker run <distro-image> bash pkg/build.sh ──►              │
│    GPG-sign artifact + manifest ──►                             │
│    push to apt/dnf repository at packages.lousclues.dev ──►    │
│    publish signed manifest to attestation index ──►            │
└─────────────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼
┌─────────────────────────────────────────────────────────────────┐
│ end user                                                        │
│                                                                 │
│  apt-get install vigil  (resolves via packages.lousclues.dev)  │
│  ──► verifies GPG signature                                     │
│  ──► (optionally) verifies signed attestation against rebuild  │
└─────────────────────────────────────────────────────────────────┘
```

The source repo's CI gate (`pkg-build.yml`) is the **only**
guarantee lousclues-pkg gets that `pkg/build.sh` will succeed. If
the gate is green on a tag, the publishing pipeline succeeds; if
it isn't, the pipeline fails fast and no broken artifact reaches
end users.

---

## Reproducibility

Two invocations of `pkg/build.sh` with the same `DISTRO`,
`VERSION`, and `SOURCE_DATE_EPOCH` **must** produce
byte-identical artifacts (sha256 match). This is enforced by
`pkg-build.yml`'s double-build + sha256-compare step and is the
foundation that makes [ATTEST.md](ATTEST.md) signed
attestations meaningful.

What the build script does to honour this:

- `LC_ALL=C`, `TZ=UTC` for deterministic ordering and timestamps;
- `cargo fetch --locked` then `cargo build --frozen --offline`
  (the second step touches no network, and the first is bounded
  by the lockfile — see the cold-registry lesson below);
- `find <stage> -exec touch -d @SOURCE_DATE_EPOCH` to normalise
  every staged file's mtime;
- `gzip -9n` (the `-n` strips the gzip header timestamp);
- for `.deb`: `strip-nondeterminism` post-processing of the
  artifact, plus `touch -h -d @SOURCE_DATE_EPOCH` of the
  `mktemp`-generated postinst before fpm reads it;
- for `.rpm`: three `rpmbuild` macros passed through fpm —
  `use_source_date_epoch_as_buildtime 1`,
  `clamp_mtime_to_source_date_epoch 1`, and
  `_buildhost reproducible.vigil-baseline.local`. The
  `strip-nondeterminism` tool is **not** used on RPM hosts (it
  has no handler for the `.rpm` file format and the underlying
  perl distribution is not on CPAN — see the lesson below).

---

## Lesson catalogue (post-spec CI iteration)

The initial 1.11.5 work shipped the spec — `pkg/build.sh`,
`pkg-build.yml`, the supporting changes (file-caps unit, dnf
hook, `vigil man`, `vigild --help`). Running that gate end-to-end
against five real distro containers surfaced eleven concrete
failure modes that the spec didn't anticipate. Each was fixed
with a targeted patch and root cause documented inline; recording
them here so the next packaging port — or anyone debugging a CI
red on this one — has the receipts.

Search this section for `**lesson:** <keyword>` to land on the
relevant rule.

### lesson: cold-registry — pair `--frozen` with explicit `cargo fetch`

`cargo build --frozen` = `--locked --offline`. On a fresh CI
runner with an empty `~/.cargo/registry/index`, it fails with
"no matching package named 'X' found" even though every dep is
pinned in `Cargo.lock`. **Fix:** split into `cargo fetch
--locked` (network allowed, lockfile pinned) followed by `cargo
build --frozen --offline` (network refused, lockfile pinned).
The build step retains its "this build touched no network" audit
property; only the fetch step is allowed to populate the local
mirror.

### lesson: apt.conf-quoting — multi-line shell goes in a separate file

`apt.conf(5)` has no escape for `"` inside `"..."` values; the
parser treats the first inner `"` as end-of-value and emits `E:
Syntax error /etc/apt/apt.conf.d/<name>:1: Extra junk after
value`, exit 100 — **which blocks every subsequent apt operation
system-wide**. **Fix:** any apt hook with multi-line shell or
quoted log messages must be split into an apt.conf config that
delegates via `test -x <path> && <path> || true` and one or
more shell scripts that hold the real logic. See `hooks/apt/`
for the canonical layout.

### lesson: fpm-reproducibility — `SOURCE_DATE_EPOCH` is necessary but not sufficient

`fpm` does not propagate `SOURCE_DATE_EPOCH` to its internal
tar/gzip/ar invocations; ar entry mtimes, gzip header timestamps,
and tar entry ordering all vary run-to-run. Additionally, a
`postinst` written from `mktemp` carries wall-clock mtime into
`control.tar.gz`. **Fix:** (a) `touch -h -d @SOURCE_DATE_EPOCH`
the postinst tempfile before fpm reads it; (b) install
`strip-nondeterminism` and run it on the artifact after fpm but
before sha256/manifest emission.

### lesson: strip-nondeterminism-is-debian-native — verify tool format support before adopting cross-distro

On Fedora/EL9, `dnf install strip-nondeterminism` fails (no such
package); `cpanm File::StripNondeterminism` *also* fails (the
distribution has never been uploaded to CPAN — metacpan's
download_url endpoint returns 404). Even if it could be
installed, `strip-nondeterminism` has **no handler for the `.rpm`
file format** — its `handlers/` tree covers ar/cpio/gzip/zip/etc.
only. **Fix:** RPM reproducibility rides entirely on three
`rpmbuild` macros (see the Reproducibility section above); don't
install `strip-nondeterminism` on RPM hosts.

### lesson: debian-dep-cascade — `dist-upgrade --allow-downgrades` not `install -f`

On bookworm/jammy GH Actions images, `apt-get install systemd
...` fails with `libcryptsetup12 (>= 2:2.4) but it is not going
to be installed`. Those container images ship with `libsystemd0`
bumped past several siblings, and apt refuses to downgrade
`libsystemd0` to match. `install -f` fixes already-installed
broken state but won't pull held libs forward. **Fix:** five-step
remediation chain — `dpkg --configure -a` → `apt-mark unhold
ALL` → explicit install of the lib set → `dist-upgrade
--allow-downgrades --allow-change-held-packages` → `install -f`,
each silenced + `|| true`.

### lesson: dep-cascade-is-per-invocation — duplicate remediation at every `apt-get` entry point

The build's own dep remediation does not transfer to a later
workflow step. After `dpkg -i --force-depends` puts apt back in a
broken-deps state, the next `apt-get install` (e.g. the
layout-verify tooling install of `coreutils libcap2-bin systemd
procps`) trips the same cascade. **Fix:** inline the same
five-step remediation chain at every `apt-get install` entry
point in the workflow, not just at build time.

### lesson: setcap-AT_SECURE — always smoke-test post-`setcap` and have a rollback path

`setcap cap_sys_admin,cap_dac_read_search+ep /usr/bin/vigild`
succeeds, but the binary then runs in secure-execution mode
(`AT_SECURE=1`), which sanitises the environment and applies a
stricter library search policy. On minimal images (incomplete
`/etc/ld.so.cache`, missing locale files) this can break even
`vigild --help`. **Fix:** in postinst, after `setcap`,
smoke-test `vigild --help`; if it fails, revert the file caps,
warn, and rely on `AmbientCapabilities=` in the unit (which the
systemd-launched daemon will pick up, since systemd runs as
root and ambient caps transfer to the child).

### lesson: systemd-man-uri — prefer `https:` over `man:` in `Documentation=`

`systemd-analyze verify` shells out to `man` to resolve `man:`
URIs. On no-TTY strict-glibc minimal containers, `man vigild(8)`
exits 16 with `Can't show vigild(8): Protocol error` even when
the page itself is fine. **Fix:** use `Documentation=https://<repo
URL>`; the https verifier parses only (no network fetch), so it
passes everywhere. Operators can still find the man page via
`man vigild` at runtime.

### lesson: usrmerge-canonical-path — use `/usr/bin/<tool>` not `/bin/<tool>`

`systemd-analyze verify` reports `Command /bin/kill is not
executable: No such file or directory` on minimal Fedora at
verify time, because the `filesystem` package may not have
fully configured the `/bin -> usr/bin` symlink yet. **Fix:** in
systemd unit files, always use the post-usrmerge canonical path
`/usr/bin/<tool>`.

### lesson: kill-is-in-procps — explicit dep for `kill(1)` on Debian

On Debian/Ubuntu, `kill(1)` ships in `procps`, not `coreutils`.
The official container images include `procps` as an "Important"
package, but a strict CI image or end-user system may not.
**Fix:** add `procps` as a runtime `--depends` on the `.deb`
package (so `systemctl reload vigild` — which invokes
`/usr/bin/kill -HUP $MAINPID` — always works) and install it
explicitly in the workflow's layout-verify tooling step. RPM
ships `kill` via `util-linux`, which systemd hard-depends on, so
no extra rpm dep is needed.

### lesson: contract-tests-not-implementation-tests — follow the contract through layout changes

When `hooks/apt/99vigil` was split into config + scripts, two
tests in `tests/hook_failure_isolation_tests.rs` failed because
they pinned to the old file (`apt_hook_references_real_vigil_path`
and `apt_hook_has_one_logger_per_failure_branch`). The contract
they asserted — "the apt hook references the real install path
AND escalates critical failures via `logger -p daemon.err`" —
still held; only the file the logic lived in had changed.
**Fix:** point the tests at the script files where the logic now
lives, not back at the old file. When a contract test reads a
specific source file, file splits are test failures even when
the contract still holds; follow the contract.

### lesson: run-fmt-after-every-edit — `cargo fmt --all --check` is a merge gate

`cargo fmt --all --check` will reject a one-line method-chain
break if rustfmt would have rendered it on a single line.
**Fix:** run `cargo fmt --all` after every test or source edit,
even tiny ones. It's free locally and red in CI.

---

## When the gate goes red

Diagnostic order (cheapest to most expensive):

1. **Layer 1 lint failure** — `shellcheck`, `bash -n`,
   `systemd-analyze verify`, apt.conf parse. Local repro: run the
   exact tool the gate ran. If it's a shellcheck false positive,
   `# shellcheck disable=<code>` with a comment explaining why is
   acceptable; if it's `systemd-analyze`, check the lesson
   catalogue above first (the `man:` URI and `/bin/kill` cases
   recur).
2. **Layer 2 negative-input failure** — `pkg/build.sh` accepted
   something it shouldn't have, or rejected something with the
   wrong exit code. Local repro: see the negative-input section
   in `.github/workflows/pkg-build.yml`. Usually means a recent
   edit to `pkg/build.sh`'s input-validation block.
3. **Layer 3 per-distro failure** — almost always one of:
   - a new file added to the source tree that the layout-check
     expects to be packaged (update `stage_assets` in
     `pkg/build.sh` and the layout-check in the workflow);
   - a missing system dep on a fresh distro image (update
     `install_{deb,rpm}_deps` in `pkg/build.sh`, and the
     remediation chain at the workflow's install entry points
     per the dep-cascade lesson);
   - an `fpm` argument that gained a default in a new release
     (pin `fpm` version in `ensure_toolchain` if drift becomes
     painful);
   - a reproducibility regression (the gate runs two passes and
     compares sha256; the failing pair is uploaded as
     `nonrepro-<distro>-{1,2}`. Diff the `fpm --inspect`
     outputs to find the entry that differs, then trace back
     through the reproducibility section above).

For all three layers, the standing rule is: **fix the root cause
in the build script or the gate, not in the artifact**. The
artifact is the output of the contract; the contract is the
thing under test.

---

## Local dry-run

You do not need to push a PR to validate `pkg/build.sh`. The
script honours `VIGIL_SKIP_DEPS=1` and `VIGIL_SKIP_TOOLCHAIN=1`,
and `pkg-build.yml`'s layer-2 negative-input tests are all
runnable as plain shell. A typical dry-run on the maintainer's
workstation:

```bash
# Layer 1: lint
shellcheck pkg/build.sh
bash -n pkg/build.sh
systemd-analyze verify systemd/vigild.service

# Layer 2: a few negative-input cases
( unset DISTRO; bash pkg/build.sh; echo "expected non-zero: $?" )
DISTRO=noble VERSION=v1.11.5 OUTDIR=/tmp/out bash pkg/build.sh
  # expected: exit 2 "leading v"

# Layer 3: real build against a shim `fpm` for a fast inner loop
rm -rf /tmp/vigil-pkg-test && mkdir -p /tmp/vigil-pkg-test
PATH=/tmp/shim:$PATH \
DISTRO=noble VERSION=$(grep '^version' Cargo.toml | head -1 | cut -d'"' -f2) \
OUTDIR=/tmp/vigil-pkg-test \
VIGIL_SKIP_DEPS=1 VIGIL_SKIP_TOOLCHAIN=1 VIGIL_KEEP_STAGE=1 \
bash pkg/build.sh

ls -la /tmp/vigil-pkg-test/
```

`VIGIL_KEEP_STAGE=1` preserves the staging tree under `target/pkg/
stage/` so you can inspect what would have been packaged.

For a real `.deb` end-to-end (slower; requires `fpm` installed
locally), drop `PATH=/tmp/shim:$PATH` and the script will use the
real `fpm`. To exercise the per-distro arms exactly as CI does,
use the matching distro image:

```bash
docker run --rm -v "$PWD:/src" -w /src ubuntu:24.04 bash -c '
  apt-get update && apt-get install -y curl ruby ruby-dev build-essential
  gem install fpm --no-document
  DISTRO=noble VERSION=1.11.5 OUTDIR=/tmp/out bash pkg/build.sh
'
```

---

## See also

- [`../pkg/README.md`](../pkg/README.md) — the strict technical
  contract (env vars, exit codes, installed-layout invariants).
- [ATTEST.md](ATTEST.md) — reproducibility and signed-attestation
  flow.
- [RELEASING.md](RELEASING.md) — the cut-a-release runbook.
- [INSTALL.md](INSTALL.md) — manual install steps for source
  builds (the path users take when they're not using the
  packages this system produces).
- [PRINCIPLES.md](PRINCIPLES.md) — "Hooks Must Never Block, but
  Must Always Be Loud" and the other principles the hook scripts
  encode.
- [`lousclues-labs/lousclues-pkg`](https://github.com/lousclues-labs/lousclues-pkg)
  — the publishing pipeline that consumes this contract.
