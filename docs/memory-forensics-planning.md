# Volatility memory-forensics plans

`plan_memory_forensics` / `plan-memory-forensics` generates an inert Volatility 3
plan for one explicit local memory image. It records the image's SHA-256 and
emits a reviewable Python script, but it does not execute Volatility, invoke
Python, parse the image, or acquire live memory.

```bash
rea plan-memory-forensics /absolute/path/to/memory.raw \
  --plugin windows.pslist --plugin windows.cmdline --json
```

MCP requires an absolute filesystem path and a non-empty plugin list:

```json
{
  "name": "plan_memory_forensics",
  "arguments": {
    "path": "/artifacts/memory.raw",
    "plugins": ["windows.pslist", "windows.cmdline"]
  }
}
```

Plugin names are passed as argument-vector entries, never as a shell command.
Names must start with a lowercase letter and may contain lowercase letters,
digits, underscores, and dots. Duplicate plugin names are rejected.

## Generated script

The script:

1. hashes the original path and stops when it differs from the planned SHA-256;
2. splits `REA_VOLATILITY_COMMAND` into an argument vector, defaulting to `vol`;
3. runs each selected plugin as `-r json -f IMAGE_PATH PLUGIN`;
4. bounds each plugin's deadline and retained stdout/stderr;
5. prints one JSON object with per-plugin status, exit code, elapsed time,
   bounded records, and stderr.

A plugin may report `ok`, `failed`, `timeout`, or `error`. Missing symbols,
unsupported operating-system versions, and incomplete images remain Volatility
observations; REA does not reinterpret them. Records are capped at 512 per
plugin and each retained stream is capped by `max_output_bytes`.

## Inputs

| Field               | Meaning                                                          |
| ------------------- | ---------------------------------------------------------------- |
| `path`              | Absolute path to the memory image                                |
| `plugins`           | 1 to 16 unique Volatility 3 plugin names                         |
| `timeout_seconds`   | Per-plugin deadline, 1 to 3600 (default 300)                     |
| `max_output_bytes`  | Retained stdout and stderr per plugin, 64 KiB to 64 MiB          |
| `max_file_bytes`    | Stable identity read bound, 64 bytes to 512 MiB (default 64 MiB) |

## Limits and unknowns

The plan does not pin Volatility, symbol tables, or the command named by
`REA_VOLATILITY_COMMAND`. A later run depends on that caller-supplied
installation and on the image's completeness, operating-system version, and
memory layout.

Recovered process, network, credential, and string records are observations from
the image. Their freshness, validity, and relation to a live system remain
unknown. Recovered secrets may be stale, decoy, or partial.

This workflow does not acquire live memory, execute the captured target, perform
taint analysis, generate exploits, change target arguments, or bypass
anti-debug, anti-VM, or integrity checks.
