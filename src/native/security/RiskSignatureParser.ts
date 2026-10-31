import { createHash } from "node:crypto";

import type { BinaryContainer, ImageSection } from "../metadata/BinaryContainer.js";
import { readBinaryContainer } from "../metadata/readBinaryContainer.js";
import {
  RISK_SIGNATURE_CATEGORIES,
  RISK_SIGNATURE_SEVERITIES,
  type InspectNativeRiskSignaturesInput,
  type NativeRiskSignatureMatch,
  type NativeRiskSignatures,
  type RiskSignatureCategory,
  type RiskSignatureEncoding,
  type RiskSignatureMatchKind,
  type RiskSignatureSeverity,
} from "../../domain/native/riskSignatures.js";

type Artifact = NativeRiskSignatures["artifact"];

interface SymbolRule {
  readonly id: string;
  readonly category: RiskSignatureCategory;
  readonly severity: RiskSignatureSeverity;
  readonly title: string;
  readonly annotation: string;
  readonly symbols: readonly string[];
}

interface PatternRule {
  readonly id: string;
  readonly category: RiskSignatureCategory;
  readonly severity: RiskSignatureSeverity;
  readonly title: string;
  readonly annotation: string;
  readonly pattern: RegExp;
  readonly redact: boolean;
}

type Rule = SymbolRule | PatternRule;

/** Raised when a caller-selected string or match budget is exhausted. */
export class RiskSignatureBudgetFailure extends Error {
  constructor(
    readonly kind: "strings" | "matches",
    readonly selected: number,
    readonly examined: number,
    message: string,
  ) {
    super(message);
    this.name = "RiskSignatureBudgetFailure";
  }
}

const annotate = (
  title: string,
  detail: string,
  category: RiskSignatureCategory,
): Pick<SymbolRule, "title" | "annotation" | "category"> => ({
  title,
  annotation: detail,
  category,
});

/**
 * Curated symbol rules. Matching is limited to whole symbol-like strings by
 * default so ordinary prose in a binary does not dominate the result.
 */
export const SYMBOL_RULES: readonly SymbolRule[] = [
  {
    id: "unsafe.strcpy",
    severity: "high",
    symbols: ["strcpy", "wcscpy"],
    ...annotate(
      "Unbounded string copy",
      "Copies until the source terminator; verify the destination capacity and source termination.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.strcat",
    severity: "high",
    symbols: ["strcat", "wcscat"],
    ...annotate(
      "Unbounded string concatenation",
      "Appends until the source terminator; verify the destination's remaining capacity.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.gets",
    severity: "high",
    symbols: ["gets"],
    ...annotate(
      "Unbounded line input",
      "Reads a line without a destination capacity; the caller cannot bound the write.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.sprintf",
    severity: "high",
    symbols: ["sprintf", "vsprintf", "wsprintfA", "wsprintfW"],
    ...annotate(
      "Unbounded formatted output",
      "Formats into an unbounded destination; prefer snprintf with an explicit size.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.stpcpy",
    severity: "medium",
    symbols: ["stpcpy", "wcpcpy"],
    ...annotate(
      "Unbounded string copy returning the terminator",
      "Copies until the source terminator; verify the destination capacity.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.strncpy",
    severity: "low",
    symbols: ["strncpy"],
    ...annotate(
      "Bounded copy may omit the terminator",
      "Copies at most n bytes and does not append NUL when the source fills the destination.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.strncat",
    severity: "medium",
    symbols: ["strncat"],
    ...annotate(
      "Bounded concatenation needs a remaining-capacity bound",
      "The size argument limits appended bytes, not the total destination size; compute remaining capacity.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.alloca",
    severity: "medium",
    symbols: ["alloca", "_alloca", "__builtin_alloca"],
    ...annotate(
      "Runtime-sized stack allocation",
      "A caller-controlled size can exhaust or collide with the stack; prefer a bounded heap allocation.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.mktemp",
    severity: "medium",
    symbols: ["mktemp", "tmpnam", "tempnam"],
    ...annotate(
      "Predictable temporary name",
      "Name generation is separate from creation, which permits races; prefer mkstemp.",
      "unsafe_memory",
    ),
  },
  {
    id: "unsafe.getwd",
    severity: "low",
    symbols: ["getwd"],
    ...annotate(
      "Unbounded current-directory retrieval",
      "The caller cannot state the destination size; prefer getcwd with an explicit buffer length.",
      "unsafe_memory",
    ),
  },
  {
    id: "exec.shell",
    severity: "high",
    symbols: ["system", "popen", "_popen", "_wsystem"],
    ...annotate(
      "Shell command execution",
      "Arguments can be interpreted by a shell; verify every input reaches this call with intended quoting.",
      "command_execution",
    ),
  },
  {
    id: "exec.family",
    severity: "medium",
    symbols: [
      "execl",
      "execle",
      "execlp",
      "execv",
      "execve",
      "execvp",
      "execvpe",
      "ShellExecuteA",
      "ShellExecuteW",
      "WinExec",
    ],
    ...annotate(
      "Process or command launch",
      "Verify the executable path, argument vector, and environment are not influenced by untrusted input.",
      "command_execution",
    ),
  },
  {
    id: "format.output",
    severity: "low",
    symbols: [
      "printf",
      "fprintf",
      "vprintf",
      "vfprintf",
      "dprintf",
      "vdprintf",
      "syslog",
    ],
    ...annotate(
      "Formatted output sink",
      "Only a format-string vulnerability when the format argument is attacker-controlled; inspect call sites.",
      "format_string",
    ),
  },
  {
    id: "format.input",
    severity: "medium",
    symbols: ["scanf", "fscanf", "sscanf", "vscanf", "vfscanf", "vsscanf"],
    ...annotate(
      "Formatted input",
      "Unbounded %s conversions can write past a destination; use explicit field widths.",
      "format_string",
    ),
  },
  {
    id: "crypto.md5",
    severity: "medium",
    symbols: ["MD5", "MD5_Init", "MD5_Update", "MD5_Final", "EVP_md5"],
    ...annotate(
      "MD5 cryptographic primitive",
      "MD5 is collision-broken; verify whether the value is used for integrity, signatures, or passwords.",
      "weak_crypto",
    ),
  },
  {
    id: "crypto.sha1",
    severity: "medium",
    symbols: ["SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final", "EVP_sha1"],
    ...annotate(
      "SHA-1 cryptographic primitive",
      "SHA-1 is collision-broken; verify whether collision resistance is required.",
      "weak_crypto",
    ),
  },
  {
    id: "crypto.des",
    severity: "medium",
    symbols: [
      "DES_set_key",
      "DES_ecb_encrypt",
      "DES_ncbc_encrypt",
      "EVP_des_cbc",
      "EVP_des_ecb",
    ],
    ...annotate(
      "DES cryptographic primitive",
      "DES has a short key and is obsolete; verify whether the data still requires protection.",
      "weak_crypto",
    ),
  },
  {
    id: "crypto.rc4",
    severity: "medium",
    symbols: ["RC4", "RC4_set_key", "EVP_rc4"],
    ...annotate(
      "RC4 stream cipher",
      "RC4 has known biases and is obsolete for new protection.",
      "weak_crypto",
    ),
  },
  {
    id: "crypto.ecb",
    severity: "medium",
    symbols: ["EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb"],
    ...annotate(
      "ECB block-cipher mode",
      "ECB reveals plaintext structure across equal blocks; verify the mode is intentional.",
      "weak_crypto",
    ),
  },
  {
    id: "dynamic.dlopen",
    severity: "low",
    symbols: ["dlopen", "dlmopen", "dlsym"],
    ...annotate(
      "Dynamic library or symbol lookup",
      "Verify the library path and symbol name are not attacker-controlled and that failures are checked.",
      "dynamic_loading",
    ),
  },
  {
    id: "dynamic.loadlibrary",
    severity: "low",
    symbols: ["LoadLibraryA", "LoadLibraryW", "GetProcAddress"],
    ...annotate(
      "Windows dynamic library or symbol lookup",
      "Verify the library path, search order, and symbol name are not attacker-controlled.",
      "dynamic_loading",
    ),
  },
  {
    id: "debug.ptrace",
    severity: "informational",
    symbols: ["ptrace"],
    ...annotate(
      "Tracing API present",
      "ptrace supports debuggers and tracers; presence does not establish anti-debug behavior.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.isdebuggerpresent",
    severity: "low",
    symbols: ["IsDebuggerPresent"],
    ...annotate(
      "Debugger-presence API present",
      "Reports whether a debugger is attached; inspect the caller to learn whether the result changes behavior.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.checkremotedebugger",
    severity: "low",
    symbols: ["CheckRemoteDebuggerPresent"],
    ...annotate(
      "Remote debugger-presence API present",
      "Reports whether another process is debugging the target; inspect the caller for behavior changes.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.ntqueryinformationprocess",
    severity: "low",
    symbols: ["NtQueryInformationProcess", "ZwQueryInformationProcess"],
    ...annotate(
      "Process-information query used by debugger checks",
      "Some information classes expose debug ports or flags; presence alone is not proof of an anti-debug check.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.ntsetinformationthread",
    severity: "low",
    symbols: ["NtSetInformationThread", "ZwSetInformationThread"],
    ...annotate(
      "Thread-information setter used by debugger checks",
      "Some information classes hide a thread from debuggers; inspect the caller before drawing conclusions.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.debugactiveprocess",
    severity: "low",
    symbols: ["DebugActiveProcess", "DebugActiveProcessStop"],
    ...annotate(
      "Debugger attachment API present",
      "Supports debugger behavior; inspect the caller to distinguish analysis tooling from anti-analysis logic.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "debug.outputdebugstring",
    severity: "informational",
    symbols: ["OutputDebugStringA", "OutputDebugStringW"],
    ...annotate(
      "Debug output API present",
      "Writes to an attached debugger; often diagnostic rather than defensive.",
      "debug_or_anti_analysis",
    ),
  },
  {
    id: "hardening.stack_chk",
    severity: "informational",
    symbols: ["__stack_chk_fail", "__stack_chk_guard"],
    ...annotate(
      "Stack canary support present",
      "Suggests stack-protector instrumentation; this is a static build indicator, not proof every function is protected.",
      "hardening",
    ),
  },
  {
    id: "hardening.fortify",
    severity: "informational",
    symbols: [
      "__memcpy_chk",
      "__memmove_chk",
      "__memset_chk",
      "__strcpy_chk",
      "__strcat_chk",
      "__sprintf_chk",
      "__snprintf_chk",
      "__printf_chk",
      "__fprintf_chk",
      "__vprintf_chk",
      "__vsprintf_chk",
    ],
    ...annotate(
      "Fortified libc wrapper present",
      "Suggests _FORTIFY_SOURCE; verify the corresponding bounded call and destination size at the call site.",
      "hardening",
    ),
  },
  {
    id: "hardening.cfi",
    severity: "informational",
    symbols: ["__cf_chk", "__cfi_check", "__cfi_slowpath"],
    ...annotate(
      "Control-flow integrity support present",
      "Suggests CFI instrumentation; coverage and enforcement remain to be verified.",
      "hardening",
    ),
  },
];

const PREFIX_RULES: readonly {
  readonly prefix: string;
  readonly rule: Omit<SymbolRule, "symbols">;
}[] = [
  {
    prefix: "__asan_",
    rule: {
      id: "hardening.asan",
      category: "hardening",
      severity: "informational",
      title: "AddressSanitizer support present",
      annotation:
        "Suggests AddressSanitizer instrumentation; the build is instrumented for analysis, not necessarily production-hardened.",
    },
  },
  {
    prefix: "__ubsan_",
    rule: {
      id: "hardening.ubsan",
      category: "hardening",
      severity: "informational",
      title: "UndefinedBehaviorSanitizer support present",
      annotation:
        "Suggests UndefinedBehaviorSanitizer instrumentation; the checked conditions are instrumentation-specific.",
    },
  },
  {
    prefix: "__msan_",
    rule: {
      id: "hardening.msan",
      category: "hardening",
      severity: "informational",
      title: "MemorySanitizer support present",
      annotation:
        "Suggests MemorySanitizer instrumentation; this does not establish runtime use.",
    },
  },
  {
    prefix: "__tsan_",
    rule: {
      id: "hardening.tsan",
      category: "hardening",
      severity: "informational",
      title: "ThreadSanitizer support present",
      annotation:
        "Suggests ThreadSanitizer instrumentation; this does not establish runtime use.",
    },
  },
  {
    prefix: "__hwasan_",
    rule: {
      id: "hardening.hwasan",
      category: "hardening",
      severity: "informational",
      title: "HWAddressSanitizer support present",
      annotation:
        "Suggests HWAddressSanitizer instrumentation; this does not establish runtime use.",
    },
  },
];

export const PATTERN_RULES: readonly PatternRule[] = [
  {
    id: "credential.private_key",
    category: "credential_pattern",
    severity: "high",
    title: "Private-key header pattern present",
    annotation:
      "A PEM private-key header is present in static bytes; the key's validity, scope, and liveness are unverified.",
    pattern: /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/u,
    redact: true,
  },
  {
    id: "credential.aws_access_key",
    category: "credential_pattern",
    severity: "medium",
    title: "AWS access-key identifier pattern present",
    annotation:
      "Matches the AWS access-key identifier shape; this does not prove the credential is active or authorized.",
    pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/u,
    redact: true,
  },
  {
    id: "credential.github_token",
    category: "credential_pattern",
    severity: "medium",
    title: "GitHub token pattern present",
    annotation:
      "Matches a GitHub token prefix and length; validity and permissions are unverified.",
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/u,
    redact: true,
  },
  {
    id: "credential.slack_token",
    category: "credential_pattern",
    severity: "medium",
    title: "Slack token pattern present",
    annotation:
      "Matches a Slack token prefix and length; validity and scope are unverified.",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/u,
    redact: true,
  },
  {
    id: "credential.jwt",
    category: "credential_pattern",
    severity: "low",
    title: "JSON Web Token pattern present",
    annotation:
      "Matches the three-part JWT shape; signature validity, issuer, and expiry are unverified.",
    pattern:
      /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/u,
    redact: true,
  },
  {
    id: "credential.password_assignment",
    category: "credential_pattern",
    severity: "medium",
    title: "Password-like assignment pattern present",
    annotation:
      "Matches a password-like assignment; this is a candidate string, not proof that a live credential exists.",
    pattern: /\b(?:password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{8,}/iu,
    redact: true,
  },
  {
    id: "credential.api_key_assignment",
    category: "credential_pattern",
    severity: "medium",
    title: "API-key-like assignment pattern present",
    annotation:
      "Matches an API-key, secret, or access-token assignment shape; validity and scope are unverified.",
    pattern:
      /\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{12,}/iu,
    redact: true,
  },
];

const baseSymbol = (raw: string): string => {
  const trimmed = raw.trim();
  const version = trimmed.indexOf("@");
  return version < 0 ? trimmed : trimmed.slice(0, version);
};

const normalizeSymbol = (raw: string): string =>
  baseSymbol(raw).replace(/^_+/u, "");

const SYMBOL_BY_NORMALIZED = new Map<string, readonly SymbolRule[]>();
for (const rule of SYMBOL_RULES)
  for (const symbol of rule.symbols) {
    const normalized = normalizeSymbol(symbol);
    const existing = SYMBOL_BY_NORMALIZED.get(normalized);
    SYMBOL_BY_NORMALIZED.set(
      normalized,
      existing === undefined ? [rule] : [...existing, rule],
    );
  }

const PREFIX_BY_PREFIX = [...PREFIX_RULES].sort(
  (left, right) => right.prefix.length - left.prefix.length,
);

const GLOBAL_PATTERN_RULES = PATTERN_RULES.map((rule) => ({
  rule,
  pattern: rule.pattern.global
    ? rule.pattern
    : new RegExp(rule.pattern.source, `${rule.pattern.flags}g`),
}));

const SYMBOL_LIKE = /^[A-Za-z_.$@][A-Za-z0-9_.$@:+-]*$/u;
const TOKEN_CHAR = /^[A-Za-z0-9_]$/u;

const isPrintable = (byte: number): boolean =>
  byte === 9 || byte === 10 || byte === 13 || (byte >= 0x20 && byte <= 0x7e);

interface ExtractedString {
  readonly offset: number;
  readonly length: number;
  readonly encoding: RiskSignatureEncoding;
  readonly text: string;
  readonly truncated: boolean;
}

interface MatchCandidate {
  readonly rule: Rule;
  readonly kind: RiskSignatureMatchKind;
  readonly offset: number;
  readonly bytes: number;
  readonly value: string | null;
  readonly preview: string;
  readonly redacted: boolean;
  readonly value_sha256: string;
}

const sha256 = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex");

const safePreview = (value: string): string => {
  const singleLine = value.replace(/[\r\n\t]+/gu, " ").trim();
  return singleLine.length <= 160 ? singleLine : `${singleLine.slice(0, 160)}…`;
};

const textLength = (value: string, encoding: RiskSignatureEncoding): number =>
  encoding === "utf16le" ? value.length * 2 : value.length;

const tokenBoundaries = (
  text: string,
  start: number,
  end: number,
): boolean => {
  const before = start === 0 ? "" : (text[start - 1] ?? "");
  const after = end >= text.length ? "" : (text[end] ?? "");
  return (
    (before === "" || !TOKEN_CHAR.test(before)) &&
    (after === "" || !TOKEN_CHAR.test(after))
  );
};

const candidateFor = (
  rule: Rule,
  kind: RiskSignatureMatchKind,
  text: string,
  string: ExtractedString,
  index: number,
  length: number,
): MatchCandidate => {
  const raw = text.slice(index, index + length);
  const offset =
    string.offset + (string.encoding === "utf16le" ? index * 2 : index);
  const bytes = textLength(raw, string.encoding);
  const digest = sha256(raw);
  if ("pattern" in rule && rule.redact)
    return {
      rule,
      kind,
      offset,
      bytes,
      value: null,
      preview: "<redacted>",
      redacted: true,
      value_sha256: digest,
    };
  return {
    rule,
    kind,
    offset,
    bytes,
    value: kind === "text" || kind === "symbol" ? raw : raw.slice(0, 256),
    preview: safePreview(raw),
    redacted: false,
    value_sha256: digest,
  };
};

const symbolCandidates = (
  text: string,
  string: ExtractedString,
  includeTextMatches: boolean,
): MatchCandidate[] => {
  const trimmed = text.trim();
  if (trimmed === "") return [];
  const trimOffset = text.indexOf(trimmed);
  const candidates: MatchCandidate[] = [];
  if (SYMBOL_LIKE.test(trimmed)) {
    const normalized = normalizeSymbol(trimmed);
    const base = baseSymbol(trimmed);
    for (const rule of SYMBOL_BY_NORMALIZED.get(normalized) ?? [])
      candidates.push(
        candidateFor(rule, "symbol", text, string, trimOffset, trimmed.length),
      );
    for (const { prefix, rule } of PREFIX_BY_PREFIX)
      if (base.startsWith(prefix))
        candidates.push(
          candidateFor(
            { ...rule, symbols: [] },
            "symbol",
            text,
            string,
            trimOffset,
            trimmed.length,
          ),
        );
    return candidates;
  }
  if (!includeTextMatches) return candidates;
  for (const rule of SYMBOL_RULES)
    for (const symbol of rule.symbols) {
      let from = 0;
      for (;;) {
        const found = text.indexOf(symbol, from);
        if (found < 0) break;
        if (tokenBoundaries(text, found, found + symbol.length))
          candidates.push(
            candidateFor(rule, "text", text, string, found, symbol.length),
          );
        from = found + symbol.length;
      }
    }
  return candidates;
};

const patternCandidates = (
  text: string,
  string: ExtractedString,
): MatchCandidate[] => {
  const candidates: MatchCandidate[] = [];
  for (const { rule, pattern } of GLOBAL_PATTERN_RULES)
    for (const match of text.matchAll(pattern)) {
      if (match.index === undefined || match[0] === "") continue;
      candidates.push(
        candidateFor(
          rule,
          "pattern",
          text,
          string,
          match.index,
          match[0].length,
        ),
      );
    }
  return candidates;
};

const decode = (
  bytes: Buffer,
  offset: number,
  length: number,
  encoding: RiskSignatureEncoding,
  maximumBytes: number,
): { text: string; truncated: boolean } => {
  const selected = Math.min(length, maximumBytes);
  const even = encoding === "utf16le" ? selected - (selected % 2) : selected;
  return {
    text: bytes.toString(encoding, offset, offset + even),
    truncated: length > even,
  };
};

interface ExtractionFacts {
  readonly examined: number;
  readonly truncated: number;
}

const extractStrings = (
  bytes: Buffer,
  input: InspectNativeRiskSignaturesInput,
  examine: (string: ExtractedString) => void,
): ExtractionFacts => {
  let examined = 0;
  let truncatedStrings = 0;
  const emit = (
    offset: number,
    length: number,
    encoding: RiskSignatureEncoding,
  ): void => {
    if (length < input.min_string_bytes) return;
    examined += 1;
    if (examined > input.max_strings)
      throw new RiskSignatureBudgetFailure(
        "strings",
        input.max_strings,
        examined,
        `The image contains more than ${String(input.max_strings)} printable string runs; raise max_strings or select a smaller artifact.`,
      );
    const { text, truncated } = decode(
      bytes,
      offset,
      length,
      encoding,
      input.max_string_bytes,
    );
    if (truncated) truncatedStrings += 1;
    if (text !== "") examine({ offset, length, encoding, text, truncated });
  };
  let start = -1;
  for (let index = 0; index < bytes.length; index++) {
    if (isPrintable(bytes[index] ?? 0)) {
      if (start < 0) start = index;
    } else if (start >= 0) {
      emit(start, index - start, "ascii");
      start = -1;
    }
  }
  if (start >= 0) emit(start, bytes.length - start, "ascii");
  for (const parity of [0, 1] as const) {
    let unicodeStart = -1;
    for (let index = parity; index + 1 < bytes.length; index += 2) {
      const valid = bytes[index + 1] === 0 && isPrintable(bytes[index] ?? 0);
      if (valid) {
        if (unicodeStart < 0) unicodeStart = index;
      } else if (unicodeStart >= 0) {
        emit(unicodeStart, index - unicodeStart, "utf16le");
        unicodeStart = -1;
      }
    }
    if (unicodeStart >= 0)
      emit(unicodeStart, (bytes.length - unicodeStart) & ~1, "utf16le");
  }
  return { examined, truncated: truncatedStrings };
};

const sectionAddress = (
  section: ImageSection,
  imageBase: bigint | undefined,
): bigint =>
  section.format === "pe"
    ? (imageBase ?? 0n) + BigInt(section.virtual_address)
    : section.address;

const overlaps = (
  address: bigint,
  size: number,
  otherAddress: bigint,
  otherSize: number,
): boolean =>
  size > 0 &&
  otherSize > 0 &&
  address < otherAddress + BigInt(otherSize) &&
  otherAddress < address + BigInt(size);

const sectionFacts = (
  container: BinaryContainer,
): NativeRiskSignatures["sections"] =>
  container.sections.map((section, index) => {
    if (section.format === "pe")
      return {
        index,
        name: section.name,
        offset: section.offset,
        size: section.size,
        file_backed: section.file_backed,
        executable: (section.characteristics & 0x20000000) !== 0,
        writable: (section.characteristics & 0x80000000) !== 0,
      };
    const address = sectionAddress(section, container.image_base);
    const region = container.load_regions?.find((candidate) =>
      overlaps(
        candidate.mapping.address,
        candidate.mapping.size,
        address,
        section.size,
      ),
    );
    return {
      index,
      name: section.name,
      offset: section.offset,
      size: section.size,
      file_backed: section.file_backed,
      executable: region === undefined ? null : region.execute,
      writable: region === undefined ? null : region.write,
    };
  });

const attributedSection = (
  orderedSections: readonly NativeRiskSignatures["sections"][number][],
  offset: number,
  bytes: number,
): string | null => {
  let best: NativeRiskSignatures["sections"][number] | undefined;
  for (const section of orderedSections) {
    if (!section.file_backed || section.size < bytes) continue;
    if (section.offset > offset) break;
    if (offset + bytes > section.offset + section.size) continue;
    if (best === undefined || section.size < best.size) best = section;
  }
  return best?.name ?? null;
};

const summary = (
  matches: readonly NativeRiskSignatureMatch[],
): NativeRiskSignatures["summary"] => {
  const categories = new Map<RiskSignatureCategory, number>();
  const severities = new Map<RiskSignatureSeverity, number>();
  for (const match of matches) {
    categories.set(match.category, (categories.get(match.category) ?? 0) + 1);
    severities.set(match.severity, (severities.get(match.severity) ?? 0) + 1);
  }
  return {
    matches: matches.length,
    by_category: RISK_SIGNATURE_CATEGORIES.map((category) => ({
      category,
      count: categories.get(category) ?? 0,
    })),
    by_severity: RISK_SIGNATURE_SEVERITIES.map((severity) => ({
      severity,
      count: severities.get(severity) ?? 0,
    })),
  };
};

/** Extract bounded printable strings and match curated native risk signatures. */
export const parseNativeRiskSignatures = (
  bytes: Buffer,
  artifact: Artifact,
  input: InspectNativeRiskSignaturesInput,
): NativeRiskSignatures => {
  const container = readBinaryContainer(bytes);
  const sections = sectionFacts(container);
  const orderedSections = [...sections].sort(
    (left, right) => left.offset - right.offset,
  );
  const retained: NativeRiskSignatureMatch[] = [];
  const seen = new Set<string>();
  const examine = (string: ExtractedString): void => {
    const candidates = [
      ...symbolCandidates(string.text, string, input.include_text_matches),
      ...patternCandidates(string.text, string),
    ];
    for (const candidate of candidates) {
      const key = `${candidate.rule.id}:${String(candidate.offset)}:${string.encoding}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (retained.length >= input.max_matches)
        throw new RiskSignatureBudgetFailure(
          "matches",
          input.max_matches,
          retained.length + 1,
          `The image produces more than ${String(input.max_matches)} retained signature matches; raise max_matches or narrow the inspection.`,
        );
      retained.push({
        rule_id: candidate.rule.id,
        category: candidate.rule.category,
        severity: candidate.rule.severity,
        title: candidate.rule.title,
        annotation: candidate.rule.annotation,
        match_kind: candidate.kind,
        encoding: string.encoding,
        offset: candidate.offset,
        bytes: candidate.bytes,
        section: attributedSection(orderedSections, candidate.offset, candidate.bytes),
        value: candidate.value,
        preview: candidate.preview,
        redacted: candidate.redacted,
        value_sha256: candidate.value_sha256,
      });
    }
  };
  const extraction = extractStrings(bytes, input, examine);
  retained.sort((left, right) =>
    left.offset === right.offset
      ? left.rule_id.localeCompare(right.rule_id)
      : left.offset - right.offset,
  );
  const partial = extraction.truncated > 0;
  return {
    artifact,
    format: container.format,
    bits: container.bits,
    architecture: container.architecture,
    byte_order: container.byte_order,
    sections,
    matches: retained,
    summary: summary(retained),
    coverage: {
      status: partial ? "partial" : "complete",
      reason: partial
        ? `${String(extraction.truncated)} printable run(s) exceeded max_string_bytes and were examined only through their prefix`
        : null,
      bytes_scanned: bytes.length,
      strings_examined: extraction.examined,
      matches_examined: retained.length,
      truncated_strings: extraction.truncated,
    },
    limitations: [
      "A symbol or pattern occurrence proves only that the bytes are present; it does not prove the code calls it, reaches it, or exposes it to untrusted input.",
      "Severity is a heuristic for triage based on the matched rule, not a validated exploitability rating.",
      "Compression, encryption, packing, and obfuscation can hide strings; absence of a match does not prove absence of the API, primitive, or credential.",
      "Credential-pattern matches are candidates only. Their values are redacted, and their validity, scope, and liveness are unverified.",
      "No disassembly, decompilation, call graph, data flow, or runtime behavior is observed.",
      ...(input.include_text_matches
        ? [
            "Text matching is enabled, so API names inside prose are reported as candidates and increase false positives.",
          ]
        : [
            "API rules match whole symbol-like strings by default; names embedded in prose require include_text_matches.",
          ]),
      ...(partial
        ? [
            `${String(extraction.truncated)} printable run(s) exceeded max_string_bytes; bytes beyond each retained prefix were not examined.`,
          ]
        : []),
    ],
  };
};
