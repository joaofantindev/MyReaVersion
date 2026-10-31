# Native taint tracing and decompilation annotations

This guide describes the existing static workflows for source-to-sink tracing
and library-pattern annotations. They reuse provider decompilation and value
tracing; REA does not ship a separate dynamic taint engine or rewrite provider
pseudocode.

## Static taint tracing

`trace_native_values` builds a bounded static dependency graph from one explicit
native procedure. It reports high-p-code def-use edges, constants, operators,
memory and branch operations, resolved call edges, and derived argument,
parameter, and return bindings.

A source-to-sink review can use it as follows:

1. Resolve an input-facing source with `find_xrefs_to_name` or
   `search_procedures`.
2. Run `trace_native_values` from that source procedure.
3. Follow `call`, `argument-binding`, and `return-binding` edges toward a sink
   such as a memory, format-string, command, or cryptographic operation.
4. Confirm the sink and its arguments with `batch_decompile` or
   `analyze_function`.
5. Read the result's `unknowns`, coverage, and per-node Evidence before drawing
   a conclusion.

This is a static dependency graph, not a whole-program taint engine. Missing
bindings, indirect calls, aliasing, persistent state, and runtime-only values
remain unknown. A path in the graph does not prove runtime reachability or
exploitability.

## Decompilation and library annotations

Provider pseudocode is available through `batch_decompile` and `decompile_all`.
REA keeps pseudocode in the provider's own terms and returns separate Evidence
for annotations:

- `inspect_native_risk_signatures` identifies unsafe APIs, command and
  format-string sinks, weak cryptography, dynamic loading, debugger APIs, and
  credential-like strings in an explicit file.
- `find_xrefs_to_name` resolves a known library name to its references.
- `trace_native_values` follows recovered dependencies across procedures.
- `batch_decompile` confirms the call site and argument expressions.

An annotation is a mapping from an observed symbol or call site to a known
library pattern. It does not rewrite pseudocode, rename provider functions, or
claim that the pattern is reachable. A matched API in an unused import table, a
string in prose, or a dead function remains static evidence only.

`decompile_all` writes complete pseudocode files and a manifest for large
reviews; use `batch_decompile` for selected functions so the reply stays bounded.

## Out-of-scope dynamic behavior

The repository excludes anti-debug, anti-VM, anti-instrumentation, DRM, and
anti-cheat evasion, as well as autonomous exploit or payload generation. Frida
planning is observation-only: it never changes arguments, return values,
registers, memory, or control flow. Symbolic, fuzzing, and memory-forensics
plans are inert text; run them only through an explicitly authorized workflow.
