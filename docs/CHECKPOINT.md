# Local acceptance — 2026-09-23

Evidence filenames and workspace-relative paths below refer to local validation records. See `../validation/README.md` for the published summary; raw local logs are not included.

A64Dispatch 1.0.0 has completed local macOS implementation and delivery
verification. This record does not claim arbitrary-input equivalence.

## Actual verification

- Baseline deflat64 `ef59221440234bee50d3061ce23fc3f8749afbbc`: isolated 88-case run.
  The migration inventory covers all 47 package Python modules and all 88 tests.
- Debug, Release, ASan/UBSan: **693 checks each**, ten CTest programs, zero failures:
  foundation 239, cleanup 17, table graph 14, flat mapping 19, sample pipeline 136,
  artifacts/process 50, workflow 78, native call models 54, comparison tree 63,
  state expansion 23.
- Neutral LLVM/LLD AArch64 fixtures execute in Unicorn with independently known
  outputs. Tests verify actual original/candidate/restored bytes, reject inverted
  conditions and incomplete branch-outcome coverage, preserve live register/
  NZCV/state effects, and follow bounded arithmetic state chains and cycles.
- Fourteen workflow commands (the original thirteen plus batch), source/config-bound
  artifact regeneration, process limits, external candidate snapshots, external
  source-bound tracing, expectations, group isolation and exact restoration run
  through the native library and CLI.
- **Real IDA 9.4: 26 checks**, rerun after the final native changes. Fresh owned-fixture
  database only. Actual six-instruction application, graph references, repeated
  apply, saved receipt resume/restore, drift and forged ownership refusal,
  pre-existing references, and injected post-mutation byte/reference failures.
- Final bounded ASan/UBSan/libFuzzer run: **860 executions / 31 seconds**, seed 9808,
  no crash or sanitizer finding. Raw instruction analysis, ELF/snapshot parsing,
  typed artifact readers, state expansion, table candidates and cleanup paths are
  included. This is a short fuzz run, not exhaustive validation.
- Installed Release CLI reports 1.0.0 and ran the 28-vector sample apply/regress/
  restore sequence. An independent C++ consumer found the installed CMake target,
  linked successfully, analyzed seven sites, applied graph metadata and restored
  the exact original fingerprint.
- Native runtime dependencies are installed separately through Homebrew; the
  dependency paths are recorded. The binary archive is not a self-contained app.

Evidence is in `../evidence/deflat64/`: build/test logs for each preset,
`baseline-inventory.json`, `ida-integration.json`, `fuzz-final.txt`, consumer logs,
installed sample receipts, runtime dependency list, source and artifact manifests.
Source and binary archives are in `../deliveries/` with SHA-256 sums.

## Deliberate boundaries

Linux and Windows execution remain OPEN. The process implementation targets POSIX;
Windows is not advertised as supported by this release. IDA tests cover version
9.4 and the owned neutral fixture, not arbitrary existing databases. Chunk ranges
remain separate; shared tails and uncertain effects conservatively prevent edits.
Models implement selected libc calls, not a complete OS, libc or device backend.
Finite known vectors and coverage checks do not prove equivalence for all inputs.
Transform state expansion and target-table enumeration enrich the graph; they do
not authorize transform byte edits. See CONFIG.md and MIGRATION.md for the exact
contracts and intentional changes from the baseline.
