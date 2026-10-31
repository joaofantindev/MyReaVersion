import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { SymbolicExecutionService } from "../application/symbolicExecution/SymbolicExecutionService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register execution-free angr plan generation and retain its Evidence. */
export const registerSymbolicExecutionTool = (
  server: EvidenceMcpServer,
  service: SymbolicExecutionService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("plan_symbolic_execution");
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
