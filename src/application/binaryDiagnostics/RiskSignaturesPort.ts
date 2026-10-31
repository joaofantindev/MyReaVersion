import type {
  ExecutionOptions,
  ProviderIdentity,
} from "../AnalysisProvider.js";
import type { AnalysisError } from "../../domain/analysisErrorBase.js";
import type {
  InspectNativeRiskSignaturesInput,
  NativeRiskSignatures,
} from "../../domain/native/riskSignatures.js";
import type { Result } from "../../domain/result.js";

/** Stable read and execution-free signature scanning, independent of a disassembler. */
export interface RiskSignaturesPort {
  readonly identity: ProviderIdentity;
  close?(): Promise<void>;
  inspect(
    input: InspectNativeRiskSignaturesInput,
    options?: ExecutionOptions,
  ): Promise<Result<NativeRiskSignatures, AnalysisError>>;
}
