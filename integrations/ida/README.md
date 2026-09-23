# IDA 9 host bridge

Evidence filenames and workspace-relative paths below refer to local validation records. See `../../validation/README.md` for the published summary; raw local logs are not included.

The native C++ program owns analysis and candidate verification. IDAPython exports
host memory and metadata, invokes that program, and applies its verified changes
on IDA's main thread. No existing user database was used for integration testing.

Load `a64dispatch_bridge.py` into IDA's Python path, then create an explicit job:

```python
import a64dispatch_bridge as bridge
job = bridge.DatabaseJob("/absolute/path/to/a64-dispatch", {
    "mode": "graph",
    "executable_regions": [{"label": ".text"}]
})
proposal = job.preview()
receipt = job.apply("graph")
job.save_receipt("/absolute/path/to/session.json")
job.restore()
```

For byte edits use linear/full mode with execution known vectors and `job.apply()`.
The bridge does not infer arguments, expected outputs, imports or executable
segments. Embedded configs are materialized dictionaries; inline observations are
accepted, while CLI-relative image/trace-file paths are not.

A new snapshot is compared with the captured original immediately before writing.
Every byte and actual newly-added user graph edge is logged. Already-existing
references are never claimed. Submission failures roll back the actual changes,
including a host call which wrote a byte before raising. Restore rejects unrelated
drift and checks native source/plan integrity before using the host log. Saved
sessions can be resumed with `DatabaseJob.resume(binary, session_path)`.

Snapshots retain user code references; automatic instruction edges are rebuilt
by the C++ decoder. The bridge neither claims ownership of automatic references
nor deletes them during restore. Function chunks are exported as separate explicit
ranges; shared chunks are deduplicated. Reanalysis is not forced during the atomic
transaction: later user changes to function ranges or references are detected as
state drift. Call models do not supply IDA decompiler or switch-info reconstruction.

`tests/integration/ida_session.py` was executed in IDA 9.4 on the independently
assembled dispatch fixture. It checks preview, actual byte application, repeated
application, saved-receipt restore, unrelated drift, forged ownership logs,
pre-existing graph references and injected byte/reference failures. The recorded
26 checks passed; see `../evidence/deflat64/ida-integration.json` from the project
root. This covers the stated fixture and host version, not arbitrary databases.
