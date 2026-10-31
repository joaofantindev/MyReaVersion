# Angr symbolic-execution plans

`plan_symbolic_execution` / `plan-symbolic-execution` generates an inert angr
symbolic-execution plan for one explicit local binary. It records the selected
artifact's SHA-256 and emits a reviewable Python script, but it does not
execute angr, invoke Python, parse the container, or run the target.

```bash
rea plan-symbolic-execution /absolute/path/to/program \
  --find-symbol win --avoid-symbol lose --symbolic-arguments 1 --json
```

MCP requires an absolute filesystem path and preserves that exact selection:

```json
{
  "name": "plan_symbolic_execution",
  "arguments": {
    "path": "/artifacts/program",
    "find": [{ "kind": "symbol", "value": "win" }],
    "avoid": [{ "kind": "symbol", "value": "lose" }],
    "symbolic_arguments": 1
  }
}
```

The CLI expresses each target as a repeated flag: `--find-address` and
`--find-symbol`, `--avoid-address` and `--avoid-symbol`. `--entry-address` or
`--entry-symbol` selects a custom start; omitting both uses the image entry
point.

## Generated script

The script uses angr's project and simulation-manager APIs. It:

1. hashes the original path and stops when it differs from the planned SHA-256;
2. opens the project with `auto_load_libs=False`;
3. resolves address targets directly and symbol targets through
   `project.loader.find_symbol`;
4. starts from `entry_state` at the selected entry;
5. optionally replaces a number of positional `argv` entries with fixed-length
   symbolic bitvectors;
6. steps until the first find target is reached, the step limit is reached, the
   deadline expires, or no active path remains;
7. prints one JSON object with status, step count, path counts, the found
   address, and bounded solved `argv` bytes.

Statuses are `found`, `exhausted`, `step-limit`, `deadline`, and `error`.
Errors name the failing stage, such as `identity`, `project`, `find`, `entry`,
or `state`.

Caller-provided paths, symbols, and values are serialized as Python data. They
are not interpolated as executable source. The script never starts a shell,
writes files, or changes the target binary.

## Inputs

| Field                        | Meaning                                                             |
| ---------------------------- | ------------------------------------------------------------------- |
| `find`                       | 1 to 8 address or symbol targets that make a path interesting       |
| `avoid`                      | Up to 16 address or symbol targets a retained path must not reach    |
| `entry`                      | Optional starting address or symbol                                 |
| `symbolic_arguments`         | Positional `argv` entries to symbolize, 0 to 8 (default 0)          |
| `max_symbolic_argument_bytes`| Fixed byte length per symbolic argument, 8 to 4096 (default 64)     |
| `max_steps`                  | Simulation-manager steps, 1 to 100000 (default 1000)                |
| `deadline_seconds`           | Checked between steps, 1 to 600 (default 60)                        |
| `max_solution_bytes`         | Retained bytes per solved argument, 1 to 4096 (default 256)         |
| `max_file_bytes`             | Stable identity read bound, 64 bytes to 512 MiB (default 64 MiB)    |

Address targets use `0x` followed by hexadecimal digits. Symbol targets are
exact loader names without NUL. Duplicate find or avoid targets, a target in
both lists, and an entry target that is also a find target are rejected before
planning.

## Limits and unknowns

A found or stopped search does not prove runtime reachability, exploitability,
or that any find target is unreachable. `entry_state` uses angr defaults and
does not reproduce the environment, files, working directory, or stdin. Only
selected `argv` entries are symbolic, with a fixed length and no explicit NUL
modelling. Solved bytes are one path's model values, not a working payload or a
stable exploit.

Shared libraries are disabled, so external calls and simulated dependencies
can differ from a native run. Python, angr, solver, loader, and ABI modelling
are caller-supplied; REA does not pin or verify that installation. The plan's
SHA-256 check catches a replaced artifact before the project loads, but a
replacement after that check is not prevented.

This workflow does not perform taint analysis, generate exploits, mutate
function arguments, or bypass anti-debug or anti-VM checks.
