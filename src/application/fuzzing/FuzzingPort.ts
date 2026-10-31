import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  FuzzingPlan,
  PlanFuzzingCampaignInput,
} from "../../domain/native/fuzzingPlan.js";
import type { Result } from "../../domain/result.js";

/** Stable target identity and execution-free AFL++ plan generation. */
export interface FuzzingPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  plan(
    input: PlanFuzzingCampaignInput,
    options?: ExecutionOptions,
  ): Promise<Result<FuzzingPlan, AnalysisError>>;
}
