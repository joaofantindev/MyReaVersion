import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected input read budget. */
export const MAX_INSPECT_RISK_SIGNATURE_FILE_BYTES = 536870912;
/** Hard ceiling on extracted string runs examined in one image. */
export const MAX_INSPECT_RISK_SIGNATURE_STRINGS = 1_000_000;
/** Hard ceiling on retained matches across every rule. */
export const MAX_INSPECT_RISK_SIGNATURE_MATCHES = 10_000;

export const RISK_SIGNATURE_CATEGORIES = [
  "unsafe_memory",
  "command_execution",
  "format_string",
  "weak_crypto",
  "dynamic_loading",
  "debug_or_anti_analysis",
  "hardening",
  "credential_pattern",
] as const;
export type RiskSignatureCategory =
  (typeof RISK_SIGNATURE_CATEGORIES)[number];

export const RISK_SIGNATURE_SEVERITIES = [
  "high",
  "medium",
  "low",
  "informational",
] as const;
export type RiskSignatureSeverity =
  (typeof RISK_SIGNATURE_SEVERITIES)[number];

export const RISK_SIGNATURE_ENCODINGS = ["ascii", "utf16le"] as const;
export type RiskSignatureEncoding =
  (typeof RISK_SIGNATURE_ENCODINGS)[number];

export const RISK_SIGNATURE_MATCH_KINDS = [
  "symbol",
  "text",
  "pattern",
] as const;
export type RiskSignatureMatchKind =
  (typeof RISK_SIGNATURE_MATCH_KINDS)[number];

/** Complete bounded static string/signature inspection of one native image. */
export const inspectNativeRiskSignaturesInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to an ELF, PE, or thin Mach-O image",
  ),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(MAX_INSPECT_RISK_SIGNATURE_FILE_BYTES)
    .default(67108864)
    .describe("Maximum stable artifact bytes to read (default 64 MiB)"),
  max_strings: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_RISK_SIGNATURE_STRINGS)
    .default(200000)
    .describe(
      "Maximum printable string runs to examine; exceeding the budget fails without partial success",
    ),
  max_matches: z
    .number()
    .int()
    .min(1)
    .max(MAX_INSPECT_RISK_SIGNATURE_MATCHES)
    .default(512)
    .describe(
      "Maximum retained signature matches; exceeding the budget fails without partial success",
    ),
  min_string_bytes: z
    .number()
    .int()
    .min(3)
    .max(64)
    .default(4)
    .describe(
      "Minimum printable run length in bytes; shorter runs are not examined",
    ),
  max_string_bytes: z
    .number()
    .int()
    .min(64)
    .max(65536)
    .default(4096)
    .describe(
      "Maximum bytes decoded from one printable run; longer runs are truncated with a limitation",
    ),
  include_text_matches: z
    .boolean()
    .default(false)
    .describe(
      "Also match API names inside prose, not only whole symbol-like strings; increases false positives",
    ),
});

const sectionSchema = z.strictObject({
  index: uint,
  name: z.string().nullable(),
  offset: uint,
  size: uint,
  file_backed: z.boolean(),
  executable: z.boolean().nullable(),
  writable: z.boolean().nullable(),
});

export const nativeRiskSignatureMatchSchema = z.strictObject({
  rule_id: z.string().min(1).max(128),
  category: z.enum(RISK_SIGNATURE_CATEGORIES),
  severity: z.enum(RISK_SIGNATURE_SEVERITIES),
  title: z.string().min(1),
  annotation: z.string().min(1),
  match_kind: z.enum(RISK_SIGNATURE_MATCH_KINDS),
  encoding: z.enum(RISK_SIGNATURE_ENCODINGS),
  offset: uint,
  bytes: uint,
  section: z.string().nullable(),
  value: z.string().nullable(),
  preview: z.string(),
  redacted: z.boolean(),
  value_sha256: digestSchema,
});

const countByCategory = z.strictObject({
  category: z.enum(RISK_SIGNATURE_CATEGORIES),
  count: uint,
});

const countBySeverity = z.strictObject({
  severity: z.enum(RISK_SIGNATURE_SEVERITIES),
  count: uint,
});

/** Observed static candidates; severity and reachability remain inferred or unknown. */
export const nativeRiskSignaturesSchema = z.strictObject({
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  format: z.enum(["elf", "pe", "macho"]),
  bits: z.union([z.literal(32), z.literal(64)]),
  architecture: z.string().min(1),
  byte_order: z.enum(["little", "big"]),
  sections: z.array(sectionSchema),
  matches: z.array(nativeRiskSignatureMatchSchema),
  summary: z.strictObject({
    matches: uint,
    by_category: z.array(countByCategory),
    by_severity: z.array(countBySeverity),
  }),
  coverage: z.strictObject({
    status: z.enum(["complete", "partial"]),
    reason: z.string().nullable(),
    bytes_scanned: uint,
    strings_examined: uint,
    matches_examined: uint,
    truncated_strings: uint,
  }),
  limitations: z.array(z.string()),
});

export type NativeRiskSignatures = z.infer<typeof nativeRiskSignaturesSchema>;
export type NativeRiskSignatureMatch = z.infer<
  typeof nativeRiskSignatureMatchSchema
>;
export type InspectNativeRiskSignaturesInput = z.infer<
  typeof inspectNativeRiskSignaturesInputSchema
>;
