# AFL++ fuzzing campaign plans

`plan_fuzzing_campaign` / `plan-fuzzing-campaign` generates an inert AFL++
campaign plan for one explicit local fuzz target. It records the target's
SHA-256 and emits a reviewable Python script, but it does not execute AFL++,
invoke Python, or run the target.

```bash
rea plan-fuzzing-campaign /absolute/path/to/parser \
  --corpus-directory /absolute/path/to/seeds \
  --output-directory /absolute/path/to/fuzz-output \
  --target-argument @@ --max-runtime-seconds 120 --json
```

MCP requires absolute paths for the target, corpus, output, and optional
dictionary:

```json
{
  "name": "plan_fuzzing_campaign",
  "arguments": {
    "path": "/artifacts/parser",
    "corpus_directory": "/artifacts/seeds",
    "output_directory": "/artifacts/fuzz-output",
    "target_arguments": ["@@"],
    "max_runtime_seconds": 120
  }
}
```

At most one target argument may be exactly `@@`; that is where AFL++ substitutes
the input file. NUL bytes are rejected.

## Generated script

The script:

1. splits `REA_AFL_FUZZ_COMMAND` into an argument vector, defaulting to
   `afl-fuzz`;
2. checks that the seed corpus directory exists;
3. hashes the target and stops when it differs from the planned SHA-256;
4. creates the output directory when needed;
5. runs AFL++ with the planned `-i`, `-o`, `-t`, `-V`, `-m`, optional `-x`, and
   target argument vector;
6. prints one JSON object with exit status, bounded stderr, and crash and hang
   file identities under `output/default/crashes` and `output/default/hangs`.

It sets `AFL_SKIP_CPUFREQ=1` and `AFL_NO_UI=1`, never starts a shell, and never
invokes REA itself.

## Crash feedback

Crash and hang files are candidate inputs, not crash reports. After a campaign
runs, use the existing inspection tools:

- `inspect_recorded_crash` on a supplied Linux core file;
- `inspect_apple_ips` on a supplied Apple `.ips` report;
- `inspect_native_risk_signatures` or `batch_decompile` to follow a candidate
  input to a static sink.

REA does not automatically replay, minimize, or exploit a candidate input.

## Inputs

| Field                  | Meaning                                                        |
| ---------------------- | -------------------------------------------------------------- |
| `path`                 | Absolute path to the fuzz target                               |
| `corpus_directory`     | Existing seed corpus directory                                 |
| `output_directory`     | AFL++ output directory; must differ from the corpus            |
| `dictionary_path`      | Optional AFL dictionary file                                   |
| `target_arguments`     | Up to 32 target arguments; at most one exact `@@`              |
| `max_runtime_seconds`  | AFL++ `-V` deadline, 1 to 86400 (default 300)                  |
| `timeout_ms`           | Per-execution timeout, 1 to 600000 (default 1000)              |
| `memory_limit_mb`      | AFL++ `-m` limit in MiB, 1 to 65536 (default 512)              |
| `max_file_bytes`       | Stable identity read bound, 64 bytes to 512 MiB (default 64 MiB) |

## Limits and unknowns

AFL++ and the target are caller-supplied and are not installed, pinned, or
verified by REA. Running the generated script executes the target; do that only
in an isolated environment with the required authorization and resource
controls.

The plan does not prove that a crash exists, that a discovered input is unique,
or that any input is exploitable. Coverage and crash triage remain unknown until
the campaign runs and its artifacts are examined.

This workflow does not perform autonomous exploit generation, taint analysis,
argument mutation, anti-debug or anti-VM bypass, or integrity-check evasion.
