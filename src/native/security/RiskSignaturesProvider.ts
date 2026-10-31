import {
  projectStableArtifactFailure,
  projectArtifactCloseFailure,
} from "../../artifacts/StableArtifactFailure.js";
import { isSelectedRegularFileError } from "../../filesystem/RegularFile.js";
import { ArtifactReaderFailure } from "../../artifacts/ArtifactReader.js";
import { readStableArtifact } from "../../artifacts/readStableArtifact.js";
import {
  artifactFilePrimaryFacts,
  type ArtifactFilePrimaryFacts,
  assertArtifactReadActive,
  artifactFileCancellationCause,
} from "../../artifacts/ArtifactFileOperation.js";
import { ArtifactResourceScope } from "../../artifacts/ArtifactResourceScope.js";
import type { RiskSignaturesPort } from "../../application/binaryDiagnostics/RiskSignaturesPort.js";
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import {
  MAX_INSPECT_RISK_SIGNATURE_FILE_BYTES,
  type InspectNativeRiskSignaturesInput,
} from "../../domain/native/riskSignatures.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok } from "../../domain/result.js";
import { NATIVE_RISK_SIGNATURES_PROVIDER } from "../../domain/investigationProviders.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";
import {
  parseNativeRiskSignatures,
  RiskSignatureBudgetFailure,
} from "./RiskSignatureParser.js";

const OPERATION = "inspect_native_risk_signatures";

/** Portable signature scanner over one bounded, identity-checked regular file. */
export class RiskSignaturesProvider implements RiskSignaturesPort {
  readonly identity = NATIVE_RISK_SIGNATURES_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        NATIVE_RISK_SIGNATURES_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async inspect(
    input: InspectNativeRiskSignaturesInput,
    options?: ExecutionOptions,
  ) {
    try {
      return await this.#resources.run(async () => {
        const snapshot = await readStableArtifact(
          input.path,
          input.max_file_bytes,
          options?.signal,
          undefined,
          this.#resources,
        );
        assertArtifactReadActive(options?.signal);
        const report = parseNativeRiskSignatures(
          snapshot.bytes,
          {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          },
          input,
        );
        assertArtifactReadActive(options?.signal);
        return ok(report);
      });
    } catch (cause) {
      return err(riskSignaturesFailure(cause, input));
    }
  }
}

const fileSizeRemediation = (input: InspectNativeRiskSignaturesInput): string =>
  input.max_file_bytes >= MAX_INSPECT_RISK_SIGNATURE_FILE_BYTES
    ? `The image exceeds the ${String(MAX_INSPECT_RISK_SIGNATURE_FILE_BYTES)}-byte input ceiling this operation accepts. Select a smaller artifact.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`;

const budgetRemediation = (
  cause: RiskSignatureBudgetFailure,
  input: InspectNativeRiskSignaturesInput,
): string =>
  cause.kind === "strings"
    ? input.max_strings >= cause.selected
      ? `The image contains more printable runs than this operation retains. Select a smaller artifact or set include_text_matches false.`
      : `Raise max_strings above ${String(input.max_strings)} or select a smaller artifact; the limit is the caller-selected string-run budget.`
    : `Raise max_matches above ${String(input.max_matches)} or narrow the inspection; the limit is the caller-selected retained-match budget.`;

const riskSignaturesFailurePrimary = (
  facts: ArtifactFilePrimaryFacts,
  input: InspectNativeRiskSignaturesInput,
): AnalysisError => {
  const { cause, origin } = facts;
  if (origin === "owned-or-classified" && cause instanceof AnalysisError)
    return cause;
  if (cause instanceof RiskSignatureBudgetFailure)
    return new AnalysisResourceConstraintError(
      OPERATION,
      "capacity",
      cause.message,
      {
        boundary: cause.kind,
        selected: cause.selected,
        examined: cause.examined,
      },
      {
        cause,
        retryable: false,
        remediationAction: budgetRemediation(cause, input),
      },
    );
  if (cause instanceof BinaryFormatFailure)
    return cause.kind === "unsupported"
      ? new AnalysisUnsupportedTargetError(
          OPERATION,
          input.path,
          cause.message,
          { cause },
        )
      : new AnalysisInputError(OPERATION, { cause }, [
          {
            path: ["path"],
            reason: "invalid_format",
            message: cause.message,
          },
        ]);
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "integrity"
  )
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      { cause },
    );
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure &&
    cause.reason === "cancelled"
  )
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
  if (
    origin === "owned-or-classified" &&
    cause instanceof ArtifactReaderFailure
  ) {
    if (cause.reason === "limit")
      return new AnalysisResourceConstraintError(
        OPERATION,
        "file-size",
        cause.message,
        { max_file_bytes: input.max_file_bytes },
        {
          cause,
          retryable: false,
          remediationAction: fileSizeRemediation(input),
        },
      );
    if (cause.reason === "path" || cause.reason === "format")
      return new AnalysisInputError(OPERATION, { cause }, [
        { path: ["path"], reason: "invalid_format", message: cause.message },
      ]);
  }
  if (cause instanceof Error && "code" in cause) {
    if (cause.code === "EACCES" || cause.code === "EPERM")
      return new AnalysisAccessDeniedError(OPERATION, input.path, cause.code, {
        cause,
      });
    if (isSelectedRegularFileError(cause))
      return new AnalysisInputError(OPERATION, { cause }, [
        {
          path: ["path"],
          reason: "invalid_value",
          message: `Selected image could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  return new ProviderAdapterError(NATIVE_RISK_SIGNATURES_PROVIDER.id, OPERATION, {
    cause,
    diagnostics: {
      path: input.path,
      reason: cause instanceof Error ? cause.message : String(cause),
    },
  });
};

const riskSignaturesFailure = (
  cause: unknown,
  input: InspectNativeRiskSignaturesInput,
): AnalysisError => {
  const primary = riskSignaturesFailurePrimary(
    artifactFilePrimaryFacts(cause),
    input,
  );
  return projectStableArtifactFailure(
    cause,
    primary,
    input.path,
    NATIVE_RISK_SIGNATURES_PROVIDER.id,
    OPERATION,
  );
};
