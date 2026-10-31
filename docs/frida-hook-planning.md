# Frida hook planning

`plan_frida_hooks` generates an observation-only Frida 17 JavaScript hook
script for caller-selected exported functions. It does not attach to a process,
load the script, or execute generated code. Planning and target instrumentation
remain separate decisions.

```json
{
  "name": "plan_frida_hooks",
  "arguments": {
    "targets": [
      {
        "module": "libc.so.6",
        "symbol": "strcpy",
        "argument_count": 2,
        "read_string_arguments": [0, 1],
        "max_string_bytes": 256
      }
    ]
  }
}
```

There is no standalone CLI command. The result contains the generated `script`,
its SHA-256 and byte length, the normalized `targets`, the required runtime,
and `limitations`. Review the script before passing its source to
`instrument_with_frida` or `load_frida_script`; those operations require their
own target instrumentation authorization.

## Generated script

Targets are resolved once when the script loads:

- a target with `module` uses `Process.findModuleByName` followed by
  `module.findExportByName`;
- a target without `module` uses `Module.findGlobalExportByName`.

Frida 17 removed the older `Module.findExportByName` and
`Module.getExportByName` forms; the planner does not emit them. A module or
export that is not present at script load is reported in the `ready` message as
missing and is not retried.

The script emits one `enter` message per call with:

- `target_id`, `module`, and `symbol` for the planned target;
- `arguments[]`, containing each selected positional argument index and its
  raw pointer value as a string;
- `string` for each index listed in `read_string_arguments`, read as bounded
  UTF-8 text.

String reads return null when the pointer is null, unreadable, or lacks a
terminator inside `max_string_bytes`. Raw pointers are addresses; their meaning
depends on the target ABI, the calling convention, and the selected function.

`onLeave` reports the raw return value when `include_return_value` is true.
Optional `include_backtrace` records up to `backtrace_depth` frames using the
accurate backtracer. The script finishes loading with a `ready` message listing
attached and missing targets.

The generated script never writes memory, replaces functions, changes
arguments, return values, registers, or control flow. Argument mutation,
anti-debug and anti-VM bypass, and integrity-check evasion are out of scope.

## Inputs

`targets` accepts 1 to 64 entries. Each target accepts:

| Field                    | Meaning                                                          |
| ------------------------ | ---------------------------------------------------------------- |
| `module`                 | Loaded module name; omit to search global exports                |
| `symbol`                 | Exported function or symbol name resolved at script load         |
| `argument_count`         | Positional arguments to report, 0 to 16 (default 0)              |
| `read_string_arguments`  | Unique argument indices to read as UTF-8, each below the count   |
| `max_string_bytes`       | Per-string read bound, 16 to 4096 (default 256)                  |
| `include_return_value`   | Report the raw return value on exit (default true)               |
| `include_backtrace`      | Report a bounded native backtrace on entry (default false)       |
| `backtrace_depth`        | Maximum retained frames, 1 to 16 (default 4)                     |

Invalid string argument indices, duplicates, or indices outside
`argument_count` are rejected before a plan is produced. Caller-provided module
and symbol names are serialized as data inside the generated script; they are
not interpolated as executable source.

## Limits and unknowns

The plan describes intended observation only. It does not prove that a hook
loaded, that a function was called, or that a reported string was complete.
Missing exports at load time are not retried. The planner does not inspect the
target module, verify symbol signatures or calling conventions, or validate
that a pointer is safe to read. Frida ABI and runtime behavior still require
real-target verification.
