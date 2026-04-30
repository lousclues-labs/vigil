# Copy.Fail Verification Executive Summary

This is the short version.

We needed proof that Vigil can detect copy.fail style page-cache tampering in a way that is real, reproducible, and evidence-backed.

That proof is now in place.

The comprehensive package now includes:

1. claim-to-evidence mapping
2. SHA-256 integrity hashes for primary artifacts
3. test validation outcome checks (summary count + zero-failure assertion)
4. verbatim captured Tier 1 and Tier 2 CLI output appendices
5. full command-output evidence snapshot appendix (verbatim)
6. full Tier 1 and Tier 2 report artifact text appendices (verbatim)

## Bottom Line

1. Vigil detected the staged modifications in both test tiers.
2. Tier 2 produced `page_cache_only`, which is the strongest copy.fail class signature in this harness design.
3. Tier 1 produced dirty-page behavior, and the in-process classifier reported `active_modification`, which is expected for that path.

## Verified Artifacts

- Tier 2 report:
  `tests/exploits/copy_fail/reports/copy_fail_20260430T015350Z.md`
- Tier 1 report:
  `tests/exploits/copy_fail/reports/copy_fail_20260430T015356Z.md`
- Harness scope and limitations:
  `tests/exploits/copy_fail/README.md`
- Full compiled report:
  `docs/COPY_FAIL_VERIFICATION_REPORT.md`

Primary integrity manifest and appendices are inside the full report.
See the Command Output Evidence Snapshot section, plus the full Tier 1/Tier 2 artifact appendices, for the added raw texture.

## Verifiable Facts From Captured Runs

- Environment:
  - Kernel `6.18.25-1-lts`
  - Vigil `1.8.1`
- Tier 2 key relation:
  - `observed != baseline`
  - `post-drop == baseline`
  - Classification: `page_cache_only`
- Tier 1 key relation:
  - dirty-page write path
  - In-process classification: `active_modification`
  - Captured Vigil CLI classification in that run: `inconclusive`

## Validation Status

Fresh rerun during report assembly:

- `cargo test --all-targets`
- `34` suite summary lines (`test result:`)
- every suite summary showed `0 failed`
- library suite summary included `368 passed; 0 failed`

Validation evidence details are included in the Command Output Evidence Snapshot appendix of the full report.

## Reproducibility

Everything needed to rerun the proof is already in-repo.

Use the command sequence in:

- `docs/COPY_FAIL_VERIFICATION_REPORT.md`

Use the checksum commands in the same report to verify artifact integrity after reruns.

## Scope Boundaries

This validation proves behavior for this tested environment and harness flow.
It does not claim universal behavior across all kernel versions, filesystems, or runtime configurations.

That boundary is intentional.
It keeps every claim precise and defensible.

## Note On Hash Display Width

The Tier artifacts currently store 16-hex hash prefixes.
That is a harness output format choice in the source artifacts, not truncation introduced by this summary.