# Local validation record

The latest 2026-09-25 re-audit passed **742 checks in the complete Release suite**
and **472 checks in seven affected groups** in each of Debug and ASan/UBSan.
It fixes logical memory-region enforcement and CLI validation before external
trace execution. Of 35 new checks, 28 failed against the preceding implementation.
The [result and sanitized transcripts](re-audit-2026-09-25/result.json) bind this
run to source and executable hashes. Debug and sanitizer did not rerun the other
three groups; no new fuzz run was performed.

The earlier 2026-09-25 review passed **707 checks** in each fresh Debug, Release and
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
The [historical IDA summary](ida-2026-09-23.json) publishes all 26 check results,
fixture/test/bridge hashes and the limits of that run. The
[host reproduction guide](../integrations/ida/README.md#reproduce-the-owned-fixture-checks)
uses a fresh disposable database. Publishing this existing record is not a new IDA run.

A separate [earlier Debug IDA result](ida-2026-09-25.json) records 26/26 checks on
2026-09-25 using the unchanged test script, the native source at `0ea2ca9`, and a
new disposable database containing only the owned assembly fixture. It records
the run times and source, Debug executable, IDA tool and fixture hashes. Actual
byte edits, graph changes and restoration passed; the temporary database was
removed and no existing user session was accessed. This was not a Release host
test or an expansion to other target binaries.

After the latest re-audit fixes, the unchanged script passed a new **26/26 Debug
IDA check** on another fresh disposable database. The
[new host record](ida-re-audit-2026-09-25.json) contains the current source hashes,
Debug executable hash and run times. The same one owned fixture was used; existing
user sessions were not accessed. Earlier host records retain their original scope.

## Current review evidence

- [Latest execution/CLI re-audit](re-audit-2026-09-25/result.json) and
  [subsequent Debug IDA result](ida-re-audit-2026-09-25.json).
- [Machine-readable review result](current-review.json) and [sanitized test transcripts](review-2026-09-25/).
- [CMake 3.24 preset compatibility result](current-review-build.json).
- [Hosted Release run 36086125433](https://github.com/dhtfish988/A64Dispatch/actions/runs/36086125433)
  passed 707 checks in ten programs and the installed consumer at commit
  [`0ea2ca926c691037a3a7c377deed4f2bbb213976`](https://github.com/dhtfish988/A64Dispatch/commit/0ea2ca926c691037a3a7c377deed4f2bbb213976).
  The [artifact summary](hosted-release-2026-09-25.json) records counts and log hashes;
  this job did not execute IDA, fuzzing, Debug or sanitizer tests.
- [GitHub macOS verification](https://github.com/dhtfish988/A64Dispatch/actions/workflows/verify.yml) builds Release, runs the tests, installs the package and exercises an independent consumer. Read the result for the exact commit; a workflow file alone is not a successful run.

The original 1.0.0 archives remain historical artifacts. Use the current Git commit
for these fixes. Earlier fuzz runs were not repeated. The native
review and the subsequent targeted Debug IDA run are separate evidence records.
