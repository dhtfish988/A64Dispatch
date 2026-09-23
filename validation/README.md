# Local validation record

A64Dispatch 1.0.0 was validated locally on macOS arm64 on 2026-09-23.
Debug, Release and ASan/UBSan each passed **693 checks**. The final bounded
fuzz run completed **860 executions in 31 seconds** without a crash or
sanitizer report. Finite tests are not an arbitrary-input equivalence proof.

The repository contains the source and reproducible tests. Full raw local logs,
build directories and private workspace material are not published. Evidence
filenames in the detailed validation documents identify the original local
records, not files promised in this repository. No hosted CI result is claimed.
Linux and Windows execution remain unverified.

`local-source-manifest.json` preserves the accepted local delivery's file hashes.
Publication edits only documentation to remove workspace-specific handoff text
and explain evidence availability. Program code, fixtures, build configuration,
tests and licenses retain their accepted bytes. The initial Git commit records
publication; it does not manufacture a prior development history.

The functional baseline is `deflat64`. Its exact commit and retained attribution
are documented in the project notices. That historical repository may be private;
licenses and source provenance remain available here.

IDA 9.4: 26 actual host checks on an owned fixture, including apply, restore and
fault rollback. Installed CLI: 28 sample vectors; a separate consumer analyzed
seven sites and restored the original graph fingerprint. See `docs/CHECKPOINT.md`.
