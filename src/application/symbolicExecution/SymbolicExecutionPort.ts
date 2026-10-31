import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  PlanSymbolicExecutionInput,
  SymbolicExecutionPlan,
} from "../../domain/native/symbolicExecutionPlan.js";
import type { Result } from "../../domain/result.js";

/** Stable artifact identity and execution-free angr plan generation. */
export interface SymbolicExecutionPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  plan(
    input: PlanSymbolicExecutionInput,
    options?: ExecutionOptions,
  ): Promise<Result<SymbolicExecutionPlan, AnalysisError>>;
}
