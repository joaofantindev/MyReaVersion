import { createHash } from "node:crypto";
import { isAbsolute } from "node:path";

import type { ExecutionOptions } from "../AnalysisProvider.js";
import type { SymbolicExecutionPort } from "./SymbolicExecutionPort.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import {
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { createEvidence, type Evidence } from "../../domain/evidence.js";
import {
  planSymbolicExecutionInputSchema,
  symbolicExecutionPlanSchema,
  type PlanSymbolicExecutionInput,
  type SymbolicExecutionPlan,
} from "../../domain/native/symbolicExecutionPlan.js";
import { err, type Result } from "../../domain/result.js";
import { completeProviderEvidence } from "../ProviderOperationExecution.js";
import { parseAnalysisInput } from "../AnalysisInput.js";

const OPERATION = "plan_symbolic_execution";

const sameTargets = (
  plan: SymbolicExecutionPlan,
  input: PlanSymbolicExecutionInput,
): boolean =>
  JSON.stringify(plan.find) === JSON.stringify(input.find) &&
  JSON.stringify(plan.avoid) === JSON.stringify(input.avoid) &&
  JSON.stringify(plan.entry) === JSON.stringify(input.entry ?? null);

const validPlan = (
  plan: SymbolicExecutionPlan,
  input: PlanSymbolicExecutionInput,
): boolean =>
  plan.artifact.path === input.path &&
  plan.artifact.bytes <= input.max_file_bytes &&
  plan.script_sha256 ===
    createHash("sha256").update(plan.script, "utf8").digest("hex") &&
  plan.script_bytes === Buffer.byteLength(plan.script, "utf8") &&
  sameTargets(plan, input) &&
  plan.limits.max_steps === input.max_steps &&
  plan.limits.deadline_seconds === input.deadline_seconds &&
  plan.limits.symbolic_arguments === input.symbolic_arguments &&
  plan.limits.max_symbolic_argument_bytes ===
    input.max_symbolic_argument_bytes &&
  plan.limits.max_solution_bytes === input.max_solution_bytes;

/** Shared caller validation, plan authentication, and Evidence provenance for CLI/MCP. */
export class SymbolicExecutionService {
  constructor(readonly provider: SymbolicExecutionPort) {}

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
      planSymbolicExecutionInputSchema,
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
    const parsed = symbolicExecutionPlanSchema.safeParse(result.value);
    if (!parsed.success || !validPlan(parsed.data, input.value))
      return err(
        new AnalysisOutputError(
          OPERATION,
          "Symbolic-execution planner returned malformed output or changed the selected targets or artifact identity.",
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
