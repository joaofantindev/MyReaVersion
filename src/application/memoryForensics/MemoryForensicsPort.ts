import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  MemoryForensicsPlan,
  PlanMemoryForensicsInput,
} from "../../domain/native/memoryForensicsPlan.js";
import type { Result } from "../../domain/result.js";

/** Stable memory-image identity and execution-free Volatility plan generation. */
export interface MemoryForensicsPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  plan(
    input: PlanMemoryForensicsInput,
    options?: ExecutionOptions,
  ): Promise<Result<MemoryForensicsPlan, AnalysisError>>;
}
