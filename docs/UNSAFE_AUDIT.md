# Unsafe Code Audit

The crate root (`src/lib.rs`) declares `#![deny(unsafe_code)]`. Every
`unsafe` block in the library is gated by an explicit
`#[allow(unsafe_code)]` on the enclosing function, impl, or module, and
every block carries a `// SAFETY:` comment explaining the invariants.

This document is the canonical inventory. Adding new `unsafe` requires a
matching entry here and a `// SAFETY:` comment on the block. Both are
enforced by review.

## Policy

1. The crate root denies unsafe code. No file may add a blanket
   `#![allow(unsafe_code)]` without justification recorded in this doc.
2. Every `unsafe { ... }` block is preceded by a `// SAFETY:` comment
   that names the syscall or operation, the invariants the caller must
   uphold, and why they hold at this call site.
3. If a safe wrapper from `nix`, `rustix`, or the standard library
   covers the operation, prefer it. Manual `libc` calls require a
   reason: missing wrapper, kernel-version probe, or fanotify-specific
   ergonomics that the wrapper does not yet expose.
4. Tests and benches are not part of the library deny boundary. The
   `tests/` and `benches/` trees may use `unsafe` in test harnesses
   without entries here, but should still carry `// SAFETY:` comments.

## Inventory

The categories below cover every `unsafe` block in `src/`. File and
line references point to the function header; individual blocks within
each function are documented inline.

### A. Process hardening syscalls

Self-imposed restrictions on the daemon process. These run once at
startup and have no memory-safety surface.

| Location | Operation | Rationale |
|----------|-----------|-----------|
| [src/daemon/mod.rs](src/daemon/mod.rs#L1027) `harden_process` | `umask(0o077)`, `prctl(PR_SET_DUMPABLE, 0)`, `prctl(PR_SET_NO_NEW_PRIVS, 1)` | Block core dumps and ptrace; refuse setuid on exec. No safe wrapper covers `prctl` constants we use. |
| [src/daemon/mod.rs](src/daemon/mod.rs#L1131) `raise_nofile_limit` | `getrlimit`, `setrlimit` (×2) | Raise `RLIMIT_NOFILE` for fanotify watch density. Stack-allocated `rlimit` struct, return code checked. |

### B. fanotify, eventfd, and file-handle resolution

The fanotify backend in `src/monitor/fanotify.rs` declares
`#![allow(unsafe_code)]` at the module level because nearly every
function calls a syscall not yet wrapped by `nix` (FID-mode events,
`open_by_handle_at`, file-handle parsing, statfs-based fsid mapping).
Every block still carries an inline `// SAFETY:` comment.

| Location | Operation |
|----------|-----------|
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L158) `EventFdGuard::drop` | `libc::close` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L180) `build_fsid_mount_map` | `statfs`, `open(O_PATH)`, `transmute` of `f_fsid` POD |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L221) `ensure_fsid_mount_fd` | same as above |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L247) `close_fsid_mount_map` | `libc::close` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L288) `start` | `SYS_fanotify_init` syscall |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L357) `start` | `eventfd` for shutdown |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L383) shutdown writer | `write` to eventfd |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L451) eventfd guard reset | `take()` of guard fd |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L622) event loop | `poll` over fanotify + eventfd |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L651) event loop | `read` of fanotify event ring |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L682) event parser | `ptr::read_unaligned` of `FanotifyEventMetadata` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L817) event parser | `OwnedFd::from_raw_fd` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L984) `mark_path` | `SYS_fanotify_mark` (full mask) |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1037) `mark_path` | `SYS_fanotify_mark` (reduced-mask retry) |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1109) FID event decode | `ptr::read_unaligned` of `FanotifyEventInfoHeader` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1133) FID event decode | `ptr::read_unaligned` of `FileHandleHeader` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1168) FID event decode | `open_by_handle_at` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1192) FID event decode | `OwnedFd::from_raw_fd` of `dir_fd` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1234) FID event decode | `ptr::read_unaligned` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1265) FID event decode | `open_by_handle_at` |
| [src/monitor/fanotify.rs](src/monitor/fanotify.rs#L1276) FID event decode | `OwnedFd::from_raw_fd` |

Tier-probing helpers in [src/monitor/mod.rs](src/monitor/mod.rs#L75)
call `SYS_fanotify_init` three times with different flag combinations
to detect FID, FidDfidName, and LegacyFd kernel support, closing each
probe fd immediately. These are documented inline with `// SAFETY:`.

`nix` 0.28 does not expose FID-mode init flags
(`FAN_REPORT_FID` / `FAN_REPORT_DFID_NAME`), `open_by_handle_at`, or
`FAN_MARK_FILESYSTEM` in a form Vigil can use. Item 4 of this audit
revisits whether newer `nix` releases close any of these gaps.

### C. mmap and page-cache forensics

`src/hash.rs` performs zero-copy BLAKE3 hashing for files above
`scanner.mmap_threshold` and the copy.fail disambiguation pass. Both
require raw `mmap` because BLAKE3 reads the buffer as a slice and the
disambiguation pass calls `posix_fadvise` and `mincore` on the same
mapping.

| Location | Operation |
|----------|-----------|
| [src/hash.rs](src/hash.rs#L34) `MmapGuard::new` | `mmap(PROT_READ, MAP_PRIVATE)` |
| [src/hash.rs](src/hash.rs#L53) `MmapGuard::as_slice` | `slice::from_raw_parts` over the mapping |
| [src/hash.rs](src/hash.rs#L62) `MmapGuard::drop` | `munmap` |
| [src/hash.rs](src/hash.rs#L80) `blake3_hash_fd` | `MmapGuard::new` |
| [src/hash.rs](src/hash.rs#L297) `disambiguate_via_cache_drop` | `posix_fadvise(POSIX_FADV_DONTNEED)` |
| [src/hash.rs](src/hash.rs#L317) | `mmap` of fixture for `mincore` |
| [src/hash.rs](src/hash.rs#L344) | `mincore` |
| [src/hash.rs](src/hash.rs#L349) | `munmap` |
| [src/hash.rs](src/hash.rs#L361) `page_size` | `sysconf(_SC_PAGESIZE)` |

`memmap2` would cover `MmapGuard` but adds a dependency for a 30-line
wrapper that the disambiguation path needs to extend with
`posix_fadvise` and `mincore` anyway. Re-evaluate if a future change
needs additional mmap call sites.

### D. Small libc wrappers

Single-syscall helpers where a safe wrapper does not exist or would
cost a dependency for one call site.

| Location | Operation |
|----------|-----------|
| [src/util/process.rs](src/util/process.rs#L11) `current_euid` | `geteuid` (cached in `OnceLock`) |
| [src/util/process.rs](src/util/process.rs#L28) `is_pid_alive` | `kill(pid, 0)` existence probe |
| [src/util/owned_fd.rs](src/util/owned_fd.rs#L20) `OwnedRawFd::drop` | `libc::close` |
| [src/util/owned_fd.rs](src/util/owned_fd.rs#L37) `OwnedRawFd::devnull` | `open("/dev/null")`, `libc::close` |
| [src/util/random.rs](src/util/random.rs#L9) `secure_bytes` | `getrandom` |
| [src/worker.rs](src/worker.rs#L67) `dup_to_file` | `fcntl(F_DUPFD_CLOEXEC)`, `File::from_raw_fd` |
| [src/control.rs](src/control.rs#L1082) `log_peer_credentials` | `getsockopt(SO_PEERCRED)` (the std `peer_cred` API is unstable on the project's MSRV) |
| [src/display/term.rs](src/display/term.rs#L57) `TermInfo::ioctl_size` | `ioctl(TIOCGWINSZ)` |

### E. Send across thread boundary

| Location | Operation |
|----------|-----------|
| [src/types/event.rs](src/types/event.rs#L30) `unsafe impl Send for FsEvent` | `OwnedFd` is `Send`; all other fields are `Send`. The fd is transferred to the worker pool and not aliased. |

### F. Tests and benches

Test code is outside the library deny boundary. The following test
files use `unsafe` in setup harnesses and carry `// SAFETY:` comments
inline:

- `tests/fanotify_fid_tier_tests.rs` -- raw fanotify init/mark for
  kernel-tier probing.
- `tests/integration_disambiguation.rs` -- `mmap`/`mincore` to fabricate
  the page-cache state under test.
- `tests/exploits/copy_fail/` -- standalone Cargo workspace (excluded
  from the main package) that exercises mmap-based page-cache poisoning
  on intentionally created fixtures. Not part of the production binary.

`benches/benchmarks.rs` contains no `unsafe`.

## Verification

```sh
# List every unsafe block in the library tree.
rg --no-heading -n 'unsafe ' src/

# Confirm every block is paired with a SAFETY comment.
rg --no-heading -n -B1 'unsafe \{' src/ | rg -B1 'SAFETY:'

# Confirm the crate root still denies unsafe.
rg '#!\[deny\(unsafe_code\)\]' src/lib.rs
```

A future automation pass should add a CI check that fails when an
`unsafe` block is added without a `// SAFETY:` comment.
