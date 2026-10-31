# Native risk signatures

`inspect_native_risk_signatures` / `inspect-native-risk-signatures` scans one
explicit local ELF, PE, or thin Mach-O image for bounded static risk
signatures. It reads the file without executing it and without a disassembler,
debug package, engine, or package catalog.

```bash
rea inspect-native-risk-signatures /absolute/path/to/program --json
```

The CLI resolves relative paths against the caller's working directory. MCP
requires an absolute filesystem path and preserves that exact selection:

```json
{
  "name": "inspect_native_risk_signatures",
  "arguments": { "path": "/artifacts/program" }
}
```

## Observations

The inline Evidence result contains the artifact path, SHA-256, and byte length,
the detected container format, bit width, architecture, and byte order, plus the
declared sections with their file offsets, sizes, and known executable or
writable flags. Section parsing identifies the byte range that contains each
match; a match outside every mapped section keeps a null section.

`matches[]` lists each retained signature match with:

- `rule_id`, `category`, `severity`, `title`, and `annotation`;
- `match_kind` (`symbol`, `text`, or `pattern`) and source `encoding`
  (`ascii` or `utf16le`);
- the original file `offset` and `bytes` length;
- a redacted `preview` and `value_sha256` of the exact matched value.

Credential-like values are redacted in `preview` and report
`value: null`, `redacted: true`. Other matches return the matched value and a
truncated preview when the value is longer than the preview budget. The SHA-256
always covers the complete matched value, so equal values can be correlated
without repeating the secret.

`summary` counts matches by category and severity. `coverage` reports whether
the complete artifact was scanned, the byte, string, and match counts examined,
and how many printable runs were truncated at `max_string_bytes`. Category,
severity, and the presence of a rule match are static observations or
heuristics. They do not establish that a function is reachable, that an input
reaches a sink, or that a credential is valid.

The curated rules cover:

- unbounded and unsafe memory APIs such as `strcpy`, `strcat`, `gets`,
  `sprintf`, `stpcpy`, `strncpy`, `strncat`, `alloca`, `mktemp`, and `getwd`;
- command execution entry points such as `system`, `popen`, and `exec*`;
- format-string output and input sinks;
- weak cryptography such as MD5, SHA-1, DES, RC4, and ECB mode;
- dynamic loading through `dlopen` and `LoadLibrary`;
- debugger and anti-analysis APIs such as `ptrace`, `IsDebuggerPresent`,
  `CheckRemoteDebuggerPresent`, and `NtQueryInformationProcess`;
- hardening instrumentation such as `__stack_chk_fail`, `__*_chk`, CFI
  checks, and sanitizer runtimes;
- credential-like patterns for private keys, cloud access keys, source-host
  tokens, JWTs, and password or API-key assignments.

Hardening rules are informational signals, not weaknesses. Debugger APIs may
be ordinary diagnostics or part of a protection scheme; this workflow reports
their presence and does not attribute intent.

## Text matching

By default, API names match only whole symbol-like strings so ordinary prose in
the image does not dominate the result. Set `include_text_matches` to also match
rule names inside longer printable runs. That mode increases false positives
and is reported in `coverage`. `min_string_bytes` (default 4) controls the
shortest printable run examined.

Both printable ASCII and UTF-16LE runs are extracted. A symbol name wrapped in
the usual leading underscore (`_strcpy`) still matches its rule, while ordinary
identifier prefixes do not.

## Limits and failures

`max_file_bytes` defaults to 64 MiB (maximum 512 MiB). `max_strings` defaults to
200,000 printable runs (maximum 1,000,000). `max_matches` defaults to 512
retained matches (maximum 10,000). `max_string_bytes` defaults to 4096 decoded
bytes per run; longer runs are truncated and counted in
`coverage.truncated_strings`. Exceeding `max_strings` or `max_matches` fails
without partial success and reports which budget was exhausted.

Malformed or unsupported containers, truncated headers, invalid section
tables, and an unreadable or changed artifact fail without Evidence. The
selected path must be an absolute regular file; symbolic links are rejected.
The operation reads an identity-checked stable snapshot and honors cancellation
during the read and scan.

A match proves only that matching bytes are present in the image. It does not
prove reachability, exploitability, runtime behavior, or credential validity.
This workflow does not execute the image, resolve imports, disassemble
functions, or contact any network service.
