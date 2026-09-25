# Implementation and delivery

The C++20 rewrite is locally delivered as A64Dispatch 1.0.0. All analysis,
configuration, instruction handling, constant tracking, state propagation, native
execution, call models, planning, verification, artifact binding and workflow logic
live in C++. IDAPython contains only host export, subprocess and database transaction
transport. Standard AArch64/IDA interfaces and inherited license notices retain
their original names; project-owned APIs and implementation structure are new.

The functional migration inventory is MIGRATION.md. CHECKPOINT.md separates the
2026-09-25 native review (Debug/Release/ASan+UBSan each 707, installed consumer and
CLI sample roundtrip) from the 2026-09-23 acceptance (693 native checks per profile,
26 IDA host checks and a short 860-execution fuzz run). A separate 2026-09-25 IDA 9.4
run passed all 26 host checks with the current Debug native binary on one new
disposable fixture database. It does not establish Release host behavior or
arbitrary-target coverage. Public evidence links are in ../validation/README.md.

Unknown effects, table instability, shared/interior entries, uncovered edited
instructions and uncovered candidate branch outcomes prevent byte commitment.
Comparison tree, native state chains, graph candidates, external observations,
regression expectations and batch isolation have concrete fixtures and refusal
cases. Restore regenerates the expected plan and metadata ownership from the
immutable captured source; it refuses unrelated drift.

The exported CMake target is A64Dispatch::a64dispatch. Dependencies and license
texts accompany the source and installed package. Platform and semantic limits
remain explicit in CHECKPOINT.md. Completion is local implementation/delivery,
not a claim of universal deobfuscation or formal program equivalence.
