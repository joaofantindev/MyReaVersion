import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { MemoryForensicsService } from "../../application/memoryForensics/MemoryForensicsService.js";
import {
  AnalysisInputError,
  AnalysisResourceConstraintError,
} from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { NATIVE_MEMORY_FORENSICS_PROVIDER } from "../../domain/investigationProviders.js";
import { memoryForensicsPlanSchema } from "../../domain/native/memoryForensicsPlan.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { MemoryForensicsProvider } from "./MemoryForensicsProvider.js";

const plan = async (
  path: string,
  input: { readonly max_file_bytes?: number } = {},
) => {
  const service = new MemoryForensicsService(new MemoryForensicsProvider());
  try {
    return await service.plan({
      path,
      plugins: ["windows.pslist"],
      ...input,
    });
  } finally {
    await service.close();
  }
};

describe("Volatility memory-forensics planner provider", () => {
  it("binds the plan to the selected image identity", async () => {
    const root = await createTestTempDirectory("rea-memory-plan-");
    const path = join(root, "memory.raw");
    const bytes = Buffer.from("selected memory bytes");
    await writeFile(path, bytes);
    const result = await plan(path);
    if (!result.ok) throw result.error;
    expect(result.value.provider).toMatchObject({
      id: NATIVE_MEMORY_FORENSICS_PROVIDER.id,
    });
    const value = memoryForensicsPlanSchema.parse(
      result.value.normalized_result,
    );
    expect(value.artifact).toEqual({
      path,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      bytes: bytes.length,
    });
    expect(value.script).toContain(JSON.stringify(path));
    expect(result.value.confidence).toBe("derived");
  });

  it("honors the caller-selected file-size budget", async () => {
    const root = await createTestTempDirectory("rea-memory-plan-budget-");
    const path = join(root, "memory.raw");
    await writeFile(path, Buffer.alloc(128));
    const result = await plan(path, { max_file_bytes: 64 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a file-size refusal");
    expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
    expect(projectAnalysisError(result.error).remediation.action).toContain(
      "max_file_bytes",
    );
  });

  it("rejects a missing selected image without producing a plan", async () => {
    const root = await createTestTempDirectory("rea-memory-plan-missing-");
    const result = await plan(join(root, "absent"));
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisInputError);
  });
});
