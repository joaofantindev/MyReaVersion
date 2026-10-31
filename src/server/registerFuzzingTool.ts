import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { FuzzingService } from "../application/fuzzing/FuzzingService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register execution-free AFL++ campaign planning and retain its Evidence. */
export const registerFuzzingTool = (
  server: EvidenceMcpServer,
  service: FuzzingService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("plan_fuzzing_campaign");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.plan(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
