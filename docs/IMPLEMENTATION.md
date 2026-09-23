# Implementation and delivery

The C++20 rewrite is locally delivered as A64Dispatch 1.0.0. All analysis,
configuration, instruction handling, constant tracking, state propagation, native
execution, call models, planning, verification, artifact binding and workflow logic
live in C++. IDAPython contains only host export, subprocess and database transaction
transport. Standard AArch64/IDA interfaces and inherited license notices retain
their original names; project-owned APIs and implementation structure are new.

The functional migration inventory is MIGRATION.md. CHECKPOINT.md records the
actual final checks: Debug/Release/ASan+UBSan each 693, real IDA 26, short fuzz 860,
installed independent C++ consumer, and installed CLI sample roundtrip. No success
is inferred from an old report or merely from compiling a bridge file.

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
