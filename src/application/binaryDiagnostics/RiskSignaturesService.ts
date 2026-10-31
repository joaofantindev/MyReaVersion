import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { RiskSignaturesPort } from "./RiskSignaturesPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  inspectNativeRiskSignaturesInputSchema,
  nativeRiskSignaturesSchema,
  type NativeRiskSignatures,
} from "../../domain/native/riskSignatures.js";
import { BINARY_ARCHITECTURES } from "../../domain/binaryTargetTypes.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "inspect_native_risk_signatures";

/** Shared caller validation, output parsing and Evidence provenance for CLI/MCP. */
export class RiskSignaturesService {
  constructor(readonly provider: RiskSignaturesPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async inspect(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      inspectNativeRiskSignaturesInputSchema,
      options?.signal,
    );
    if (!input.ok) return input;
    if (!isAbsolute(input.value.path))
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.inspect(input.value, options);
    if (!result.ok) return result;
    const report = nativeRiskSignaturesSchema.safeParse(result.value);
    if (
      !report.success ||
      report.data.artifact.path !== input.value.path ||
      !validReport(report.data, input.value)
    )
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Native risk-signature provider returned malformed output or changed artifact identity.",
        ),
      );
    const value = report.data;
    const architecture = BINARY_ARCHITECTURES.find(
      (supported) => supported === value.architecture,
    );
    return completeProviderEvidence(
      createEvidence(
        {
          path: value.artifact.path,
          format: value.format === "macho" ? "mach-o" : value.format,
          sha256: value.artifact.sha256,
          ...(architecture === undefined ? {} : { architecture }),
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.value,
          result: value,
          confidence: "observed",
          limitations: value.limitations,
          locations: [
            { kind: "artifact-path", path: value.artifact.path },
            ...value.matches.map((match) => ({
              kind: "file-offset-range" as const,
              start: match.offset,
              end: match.offset + match.bytes,
            })),
          ],
        },
      ),
      options?.signal,
    );
  }
}

const validReport = (
  report: NativeRiskSignatures,
  input: {
    readonly max_file_bytes: number;
    readonly max_strings: number;
    readonly max_matches: number;
  },
): boolean => {
  const inside = ({ offset, bytes }: { offset: number; bytes: number }) =>
    offset <= report.artifact.bytes - bytes;
  const summaryMatches = report.summary.by_category.reduce(
    (total, row) => total + row.count,
    0,
  );
  const summarySeverities = report.summary.by_severity.reduce(
    (total, row) => total + row.count,
    0,
  );
  return (
    report.artifact.bytes <= input.max_file_bytes &&
    report.matches.length === report.coverage.matches_examined &&
    report.matches.length === report.summary.matches &&
    summaryMatches === report.matches.length &&
    summarySeverities === report.matches.length &&
    report.coverage.strings_examined <= input.max_strings &&
    report.matches.length <= input.max_matches &&
    report.coverage.bytes_scanned === report.artifact.bytes &&
    report.coverage.truncated_strings <= report.coverage.strings_examined &&
    report.sections.every(
      (section) => section.offset <= report.artifact.bytes - section.size,
    ) &&
    report.matches.every(
      (match) =>
        inside(match) &&
        (match.redacted ? match.value === null : true) &&
        /^[a-f0-9]{64}$/u.test(match.value_sha256),
    )
  );
};
