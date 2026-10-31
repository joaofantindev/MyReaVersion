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
import type { MemoryForensicsPort } from "../../application/memoryForensics/MemoryForensicsPort.js";
import {
  AnalysisAccessDeniedError,
  AnalysisArtifactChangedError,
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import {
  MAX_PLAN_MEMORY_FORENSICS_FILE_BYTES,
  type PlanMemoryForensicsInput,
} from "../../domain/native/memoryForensicsPlan.js";
import { ProviderAdapterError } from "../../domain/providerAdapterError.js";
import { err, ok } from "../../domain/result.js";
import { NATIVE_MEMORY_FORENSICS_PROVIDER } from "../../domain/investigationProviders.js";
import { planMemoryForensics } from "../../application/memoryForensics/MemoryForensicsPlanner.js";

const OPERATION = "plan_memory_forensics";

const fileSizeRemediation = (input: PlanMemoryForensicsInput): string =>
  input.max_file_bytes >= MAX_PLAN_MEMORY_FORENSICS_FILE_BYTES
    ? `The image exceeds the ${String(MAX_PLAN_MEMORY_FORENSICS_FILE_BYTES)}-byte input ceiling this operation accepts. Select a smaller artifact.`
    : `Raise max_file_bytes above ${String(input.max_file_bytes)} bytes or select a smaller artifact; the limit is the caller-selected input read budget.`;

/** Identity-checked image read followed by inert plan generation. */
export class MemoryForensicsProvider implements MemoryForensicsPort {
  readonly identity = NATIVE_MEMORY_FORENSICS_PROVIDER;
  readonly #resources = new ArtifactResourceScope();

  async close(): Promise<void> {
    try {
      await this.#resources.close();
    } catch (cause: unknown) {
      throw projectArtifactCloseFailure(
        cause,
        NATIVE_MEMORY_FORENSICS_PROVIDER.id,
        OPERATION,
      );
    }
  }

  async plan(
    input: PlanMemoryForensicsInput,
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
          planMemoryForensics(input, {
            path: input.path,
            sha256: snapshot.sha256,
            bytes: snapshot.bytes.length,
          }),
        );
      });
    } catch (cause) {
      return err(memoryPlanFailure(cause, input));
    }
  }
}

const memoryPlanFailurePrimary = (
  facts: ArtifactFilePrimaryFacts,
  input: PlanMemoryForensicsInput,
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
          message: `Selected memory image could not be read (${String(cause.code)}): ${input.path}.`,
        },
      ]);
  }
  if (
    origin !== "owned-or-classified" ||
    !(cause instanceof ArtifactReaderFailure)
  )
    return new ProviderAdapterError(
      NATIVE_MEMORY_FORENSICS_PROVIDER.id,
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

const memoryPlanFailure = (
  cause: unknown,
  input: PlanMemoryForensicsInput,
) =>
  projectStableArtifactFailure(
    cause,
    memoryPlanFailurePrimary(artifactFilePrimaryFacts(cause), input),
    input.path,
    NATIVE_MEMORY_FORENSICS_PROVIDER.id,
    OPERATION,
  );
