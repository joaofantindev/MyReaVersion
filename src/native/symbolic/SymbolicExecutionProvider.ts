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
import type { ExecutionOptions } from "../../application/AnalysisProvider.js";
import type { SymbolicExecutionPort } from "../../application/symbolicExecution/SymbolicExecutionPort.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import {
  MAX_PLAN_SYMBOLIC_EXECUTION_FILE_BYTES,
  type PlanSymbolicExecutionInput,
} from "../../domain/native/symbolicExecutionPlan.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok } from "../../domain/result.js";
import { NATIVE_SYMBOLIC_EXECUTION_PROVIDER } from "../../domain/investigationProviders.js";
import { planSymbolicExecution } from "../../application/symbolicExecution/SymbolicExecutionPlanner.js";

const OPERATION = "plan_symbolic_execution";

const fileSizeRemediation = (
  input: PlanSymbolicExecutionInput,
): string =>
  input.max_file_bytes >= MAX_PLAN_SYMBOLIC_EXECUTION_FILE_BYTES
    ? `The image exceeds the ${String(MAX_PLAN_SYMBOLIC_EXECUTION_FILE_BYTES)}-byte input ceiling this operation accepts. Select a smaller artifact.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`;

/** Identity-checked artifact read followed by inert plan generation. */
export class SymbolicExecutionProvider implements SymbolicExecutionPort {
  readonly identity = NATIVE_SYMBOLIC_EXECUTION_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        NATIVE_SYMBOLIC_EXECUTION_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async plan(
    input: PlanSymbolicExecutionInput,
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
        return ok(
          planSymbolicExecution(input, {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          }),
        );
      });
    } catch (cause) {
      return err(symbolicPlanFailure(cause, input));
    }
  }
}

const symbolicPlanFailurePrimary = (
  facts: ArtifactFilePrimaryFacts,
  input: PlanSymbolicExecutionInput,
) => {
  const { cause, origin } = facts;
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
          message: `Selected binary could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  if (
    origin !== "owned-or-classified" ||
    !(cause instanceof ArtifactReaderFailure)
  )
    return new ProviderAdapterError(
      NATIVE_SYMBOLIC_EXECUTION_PROVIDER.id,
      OPERATION,
      {
        cause,
        diagnostics: {
          path: input.path,
          reason: cause instanceof Error ? cause.message : String(cause),
        },
      },
    );
  if (cause.reason === "integrity")
    return new AnalysisArtifactChangedError(
      OPERATION,
      input.path,
      cause.message,
      { cause },
    );
  if (cause.reason === "cancelled")
    return new AnalysisCancelledError(OPERATION, {
      cause: artifactFileCancellationCause(cause),
    });
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
  return new AnalysisInputError(OPERATION, { cause }, [
    { path: ["path"], reason: "invalid_format", message: cause.message },
  ]);
};

const symbolicPlanFailure = (
  cause: unknown,
  input: PlanSymbolicExecutionInput,
) =>
  projectStableArtifactFailure(
    cause,
    symbolicPlanFailurePrimary(artifactFilePrimaryFacts(cause), input),
    input.path,
    NATIVE_SYMBOLIC_EXECUTION_PROVIDER.id,
    OPERATION,
  );
