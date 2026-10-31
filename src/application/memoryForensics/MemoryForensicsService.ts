import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { MemoryForensicsPort } from "./MemoryForensicsPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  memoryForensicsPlanSchema,
  planMemoryForensicsInputSchema,
  type MemoryForensicsPlan,
  type PlanMemoryForensicsInput,
} from "../../domain/native/memoryForensicsPlan.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "plan_memory_forensics";

const validPlan = (
  plan: MemoryForensicsPlan,
  input: PlanMemoryForensicsInput,
): boolean =>
  plan.artifact.path === input.path &&
  plan.artifact.bytes <= input.max_file_bytes &&
  plan.script_sha256 ===
    createHash("sha256").update(plan.script, "utf8").digest("hex") &&
  plan.script_bytes === Buffer.byteLength(plan.script, "utf8") &&
  JSON.stringify(plan.runtime.plugins.map(({ name }) => name)) ===
    JSON.stringify(input.plugins) &&
  plan.limits.timeout_seconds === input.timeout_seconds &&
  plan.limits.max_output_bytes === input.max_output_bytes;

/** Shared caller validation, plan authentication, and Evidence provenance for CLI/MCP. */
export class MemoryForensicsService {
  constructor(readonly provider: MemoryForensicsPort) {}

  close(): Promise<void> {
    return this.provider.close?.() ?? Promise.resolve();
  }

  async plan(
    rawInput: unknown,
    options?: ExecutionOptions,
  ): Promise<Result<Evidence, AnalysisError>> {
    const input = parseAnalysisInput(
      OPERATION,
      rawInput,
      planMemoryForensicsInputSchema,
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
    const result = await this.provider.plan(input.value, options);
    if (!result.ok) return result;
    const parsed = memoryForensicsPlanSchema.safeParse(result.value);
    if (!parsed.success || !validPlan(parsed.data, input.value))
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Memory-forensics planner returned malformed output or changed the selected plugins or artifact identity.",
        ),
      );
    const plan = parsed.data;
    return completeProviderEvidence(
      createEvidence(
        {
          path: plan.artifact.path,
          format: "file",
          sha256: plan.artifact.sha256,
        },
        this.provider.identity,
        {
          operation: OPERATION,
          parameters: input.value,
          result: plan,
          confidence: "derived",
          limitations: plan.limitations,
          locations: [{ kind: "artifact-path", path: plan.artifact.path }],
        },
      ),
      options?.signal,
    );
  }
}
