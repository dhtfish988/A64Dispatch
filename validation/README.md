# Local validation record

The 2026-09-25 review passed **707 checks** in each fresh Debug, Release and
ASan/UBSan build on macOS arm64. Fourteen checks cover candidate verification
and mandatory direct-branch target metadata; nine failed against the pre-fix
source. A fresh installed CLI and independent consumer also passed.
See [the current verification record](../docs/CHECKPOINT.md).

A64Dispatch 1.0.0 was initially validated locally on macOS arm64 on 2026-09-23.
Debug, Release and ASan/UBSan each passed **693 checks**. The final bounded
fuzz run completed **860 executions in 31 seconds** without a crash or
sanitizer report. Finite tests are not an arbitrary-input equivalence proof.

The repository contains the source and reproducible tests. Full raw local logs,
build directories and private workspace material are not published. Evidence
filenames in the detailed validation documents identify the original local
records, not files promised in this repository. Selected transcripts for the current
review are published below; full raw local evidence remains outside the repository.
Linux and Windows execution remain unverified.

`local-source-manifest.json` preserves the accepted local delivery's file hashes.
The initial publication edited only documentation to remove workspace-specific handoff text
and explain evidence availability. Program code, fixtures, build configuration,
tests and licenses initially retained their accepted bytes. Subsequent Git commits
record later fixes; this manifest is historical and does not describe the current checkout. The initial Git commit records
publication; it does not manufacture a prior development history.

The functional baseline is `deflat64`. Its exact commit and retained attribution
are documented in the project notices. That historical repository may be private;
licenses and source provenance remain available here.

Historical IDA 9.4 result (2026-09-23): 26 actual host checks on an owned fixture, including apply, restore and
fault rollback. Installed CLI: 28 sample vectors; a separate consumer analyzed
seven sites and restored the original graph fingerprint. See `docs/CHECKPOINT.md`.

## Current review evidence

- [Machine-readable review result](current-review.json) and [sanitized test transcripts](review-2026-09-25/).
- [CMake 3.24 preset compatibility result](current-review-build.json).
- [GitHub macOS verification](https://github.com/dhtfish988/A64Dispatch/actions/workflows/verify.yml) builds Release, runs the tests, installs the package and exercises an independent consumer. Read the result for the exact commit; a workflow file alone is not a successful run.

The original 1.0.0 archives remain historical artifacts. Use the current Git commit
for these fixes. This review did not repeat earlier fuzz, system-corpus or IDA runs.
