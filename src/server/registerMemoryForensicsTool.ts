import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import type { MemoryForensicsService } from "../application/memoryForensics/MemoryForensicsService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { Logger } from "pino";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Register execution-free Volatility plan generation and retain its Evidence. */
export const registerMemoryForensicsTool = (
  server: EvidenceMcpServer,
  service: MemoryForensicsService,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const contract = toolContract("plan_memory_forensics");
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
