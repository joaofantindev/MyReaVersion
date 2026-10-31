import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { FuzzingPort } from "./FuzzingPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  fuzzingPlanSchema,
  planFuzzingCampaignInputSchema,
  type FuzzingPlan,
  type PlanFuzzingCampaignInput,
} from "../../domain/native/fuzzingPlan.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "plan_fuzzing_campaign";

const validPlan = (
  plan: FuzzingPlan,
  input: PlanFuzzingCampaignInput,
): boolean =>
  plan.artifact.path === input.path &&
  plan.artifact.bytes <= input.max_file_bytes &&
  plan.script_sha256 ===
    createHash("sha256").update(plan.script, "utf8").digest("hex") &&
  plan.script_bytes === Buffer.byteLength(plan.script, "utf8") &&
  JSON.stringify(plan.runtime.target_arguments) ===
    JSON.stringify(input.target_arguments) &&
  plan.campaign.corpus_directory === input.corpus_directory &&
  plan.campaign.output_directory === input.output_directory &&
  plan.campaign.dictionary_path === (input.dictionary_path ?? null) &&
  plan.limits.max_runtime_seconds === input.max_runtime_seconds &&
  plan.limits.timeout_ms === input.timeout_ms &&
  plan.limits.memory_limit_mb === input.memory_limit_mb;

/** Shared caller validation, plan authentication, and Evidence provenance for CLI/MCP. */
export class FuzzingService {
  constructor(readonly provider: FuzzingPort) {}

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
      planFuzzingCampaignInputSchema,
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
    if (
      !isAbsolute(input.value.corpus_directory) ||
      !isAbsolute(input.value.output_directory)
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: [
              !isAbsolute(input.value.corpus_directory)
                ? "corpus_directory"
                : "output_directory",
            ],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    if (
      input.value.dictionary_path !== undefined &&
      !isAbsolute(input.value.dictionary_path)
    )
      return err(
        new AnalysisInputError(OPERATION, undefined, [
          {
            path: ["dictionary_path"],
            reason: "invalid_format",
            message: "Expected an absolute filesystem path on this host.",
          },
        ]),
      );
    const result = await this.provider.plan(input.value, options);
    if (!result.ok) return result;
    const parsed = fuzzingPlanSchema.safeParse(result.value);
    if (!parsed.success || !validPlan(parsed.data, input.value))
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Fuzzing planner returned malformed output or changed the selected target, campaign, or artifact identity.",
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
