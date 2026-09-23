# A64Dispatch

A C++20 library and CLI for AArch64 dispatch analysis, control-flow reports and
verified same-size branch rewriting. Version 1.0.0 is validated locally on macOS arm64.
The [validation summary](validation/README.md) records the local acceptance
scope and explains availability of the detailed evidence.

The native library currently provides mapped ELF64/snapshot/flat-file inputs, instruction
semantics, bounded constant and binary-choice tracking, two-level and single-level
table dispatch analysis, experimental comparison-tree recovery, static and observed
target grading, native Unicorn execution, branch planning and an in-memory rewrite
transaction. The CLI now includes source-bound staged artifacts, full workflow, graph ownership,
restore/regression, command oracles, bounded libc call models and cleanup proposals.
Comparison-tree conditional back edges, bounded state expansion, table graph
candidates, external traces, independent batch jobs and regression expectations
are implemented and exercised. See the [migration inventory](docs/MIGRATION.md).

Candidate verification executes the original and modified image separately, checks
known outputs and requires coverage of changed instructions and the proposed
indirect-branch targets. Finite examples do not establish equivalence for all inputs.
The library rejects unsupported reasoning cases instead of substituting a guess.

## Development build

Validated local dependencies are available with Homebrew:

```sh
brew install cmake ninja pkgconf nlohmann-json libgcrypt capstone unicorn yaml-cpp llvm lld
cmake --preset debug
cmake --build --preset debug
ctest --preset debug --verbose
```

The test build compiles the neutral AArch64 assembly in `samples/dispatch_cases.S`
using a cross-target LLVM compiler and ELF linker. A separate IDA 9.4 database was
created from this fixture for 26 successful host integration checks, including
actual byte/graph application, restoration and injected host failures. Native Debug, Release
and ASan/UBSan each pass 693 checks. An independent installed C++ consumer has
executed the library and exact graph restoration. Linux/Windows execution is OPEN.

Current development commands:

```sh
build/debug/a64-dispatch decode 0xb8a95948 0x100000
build/debug/a64-dispatch snapshot build/debug/dispatch_cases.elf snapshot.json
build/debug/a64-dispatch resolve --image build/debug/dispatch_cases.elf --config samples/settings.json --output analysis.json
build/debug/a64-dispatch run --config samples/workflow.json --output build/preview.json
build/debug/a64-dispatch run --config samples/workflow.json --apply --output build/applied.json
build/debug/a64-dispatch regress --config samples/workflow.json --output build/regression.json
build/debug/a64-dispatch restore --config samples/workflow.json --from build/applied.json --output build/restored.json
```

`survey` and `classify` select earlier stages. `--from` checks a prior stage against
fresh source/configuration analysis. The CLI returns separate snapshots; the thin
IDA adapter explicitly submits verified changes to its database. Read
[configuration and protocol details](docs/CONFIG.md), the [IDA bridge guide](integrations/ida/README.md),
and [validation record](docs/CHECKPOINT.md).

## Sources and licensing

The functional baseline is deflat64 commit
`ef59221440234bee50d3061ce23fc3f8749afbbc`, itself based on DumpA1n's MIT-licensed
[unflatten64](https://github.com/DumpA1n/unflatten64). That baseline's pure Python
suite was rerun in an isolated copy: 88 cases passed. Its unvalidated IDA paths are
replaced and tested locally; they are not treated as established correctness evidence.

New implementation: copyright 2026 dhtfish98, licensed under GPL-2.0-only. The
native build links Unicorn; this distribution retains its GPL license together
with dependency notices. The inherited baseline MIT attribution remains in
`licenses/deflat64-MIT.txt`. No third-party target binaries or private target data
are included in the source tree.

## Install and use the library

```sh
cmake --preset release
cmake --build --preset release
ctest --preset release --verbose
cmake --install build/release --prefix "$PWD/dist/A64Dispatch-macos-arm64"
cmake -S examples/consumer -B build/consumer -DCMAKE_PREFIX_PATH="$PWD/dist/A64Dispatch-macos-arm64"
cmake --build build/consumer
build/consumer/consumer build/release/dispatch_cases.elf
```

The installed CMake target is `A64Dispatch::a64dispatch`. Native binary archives
include the program, worker, static library, headers, host adapter, docs, examples
and licenses. Homebrew runtime dependencies are installed separately; the archive
is not a self-contained macOS application. See dependencies.lock.json and the
runtime dependency record in the delivery evidence.

Local validation and publication scope: [validation/README.md](validation/README.md).
