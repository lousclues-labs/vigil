<!-- SPDX-License-Identifier: GPL-3.0-only -->

# `pkg/`: vigil's pkg-framework manifest

This directory contains vigil's adoption of
[pkg-framework](https://github.com/lousclues-labs/pkg-integration), the
shared deb/rpm build pipeline for lousclues-labs Rust projects. The
framework is vendored at `pkg/lib/`; the version pin lives in
`pkg/project.sh` as `FRAMEWORK_VERSION`.

## Layout

```
pkg/
  build.sh              thin wrapper; do not edit
  project.sh            vigil's manifest + hooks (the real config)
  lib/
    framework.sh        vendored from pkg-framework
    layout-check.sh     vendored
    input-tests.sh      vendored
    VERSION             vendored framework version (1.2.2)
```

`pkg/build.sh` is the source-project contract that `lousclues-pkg`
invokes at release time:

```sh
DISTRO=noble VERSION=1.12.0 OUTDIR=/tmp/out bash pkg/build.sh
```

Supported `DISTRO` values: `noble`, `jammy`, `bookworm`, `el9`,
`fedora`. Each invocation emits exactly one `.deb` or `.rpm` into
`OUTDIR` plus a `.manifest.json` sidecar. The gate workflow at
`.github/workflows/pkg-build.yml` runs this contract on every PR
that touches packaging-relevant paths.

## Updating the vendored framework

```sh
pkg-framework sync --bump
```

Read the framework's
[CHANGELOG](https://github.com/lousclues-labs/pkg-integration/blob/main/CHANGELOG.md)
and the [upgrade procedure](https://github.com/lousclues-labs/pkg-integration/blob/main/docs/versioning.md)
before bumping across a minor version.

After sync:

```sh
pkg-framework verify        # drift gate
pkg-framework lint          # manifest schema check
pkg-framework status        # one-line summary
```

The CI gate runs the same three commands; local-clean is necessary
but not sufficient.

## Vigil-specific customizations

Everything vigil needs beyond the framework's defaults lives in
`pkg/project.sh` as `project_*` hooks. The substantive ones:

| Hook | Purpose |
|---|---|
| `project_pre_install_deb_deps` | Runs `scripts/fix-debian-deps.sh` for the libsystemd0 version-skew remediation. |
| `project_post_build` | Generates bash/zsh/fish completions and gzipped man pages (`vigil.1`, `vigil.toml.5`, `vigild.8`) from the freshly built `vigil` binary. |
| `project_stage_extra` | Stages the example config, `hooks/apt/*` (deb only), `hooks/dnf/*` (rpm only), generated completions, and generated man pages. |
| `project_postinst_body` | `setcap cap_sys_admin,cap_dac_read_search+ep` on `/usr/bin/vigild` with a `--help` self-test and a revert path. |
| `project_fpm_rpm_extra_args` | Passes the three rpmbuild macros needed for sha256-reproducible rpms. |
| `project_install_layout_check_extra` | Five post-install gates: capability presence, apt-hook cycle integrity, dnf-plugin pair integrity, `systemd-analyze verify`, and `vigil --version` smoke. |

## Archived pre-framework files

The previous custom `pkg/build.sh` (747 lines) and
`.github/workflows/pkg-build.yml` (748 lines) are preserved at
`.archive/` for the duration of the framework migration. Once the
framework path has shipped one real release cleanly they can be
removed.

## Reference

- Framework: <https://github.com/lousclues-labs/pkg-integration>
- Porting guide: <https://github.com/lousclues-labs/pkg-integration/blob/main/docs/porting-guide.md>
- Customization surface: <https://github.com/lousclues-labs/pkg-integration/blob/main/docs/customization-surface.md>
- Attestation contract (vigil): [`docs/ATTEST.md`](../docs/ATTEST.md)
