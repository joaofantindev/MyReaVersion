import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { RiskSignaturesService } from "../../application/binaryDiagnostics/RiskSignaturesService.js";
import {
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../../domain/analysisErrorCore.js";
import { projectAnalysisError } from "../../domain/analysisErrorProjection.js";
import { nativeRiskSignaturesSchema } from "../../domain/native/riskSignatures.js";
import { NATIVE_RISK_SIGNATURES_PROVIDER } from "../../domain/investigationProviders.js";
import { createTestTempDirectory } from "../../../tests/fixtures/temporaryDirectory.js";
import { elfNoteFixture, gnuBuildIdNote } from "../elf/ElfNotes.fixture.js";
import { RiskSignaturesProvider } from "./RiskSignaturesProvider.js";

const image = (...values: readonly string[]): Buffer =>
  elfNoteFixture({
    notes: Buffer.concat([
      gnuBuildIdNote(),
      Buffer.from(values.map((value) => `\0${value}\0`).join(""), "latin1"),
    ]),
  });

const inspect = async (
  path: string,
  input: {
    readonly max_file_bytes?: number;
    readonly max_matches?: number;
  } = {},
) => {
  const service = new RiskSignaturesService(new RiskSignaturesProvider());
  try {
    return await service.inspect({ path, ...input });
  } finally {
    await service.close();
  }
};

describe("native risk-signature provider", () => {
  it("scans a real ELF fixture and retains an evidence-backed match", async () => {
    const root = await createTestTempDirectory("rea-risk-signatures-");
    const path = join(root, "program");
    await writeFile(path, image("strcpy", "AKIAABCDEFGHIJKLMNOP"));
    const result = await inspect(path);
    if (!result.ok) throw result.error;
    expect(result.value.provider).toMatchObject({
      id: NATIVE_RISK_SIGNATURES_PROVIDER.id,
    });
    const report = nativeRiskSignaturesSchema.parse(
      result.value.normalized_result,
    );
    expect(report.artifact).toMatchObject({ path, bytes: expect.any(Number) });
    expect(report.matches).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "unsafe.strcpy",
          section: ".note.gnu.build-id",
        }),
        expect.objectContaining({
          rule_id: "credential.aws_access_key",
          redacted: true,
          value: null,
        }),
      ]),
    );
    expect(result.value.locations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "artifact-path", path }),
        expect.objectContaining({ kind: "file-offset-range" }),
      ]),
    );
  });

  it("names the retained-match budget and offers a bounded remediation", async () => {
    const root = await createTestTempDirectory("rea-risk-signatures-budget-");
    const path = join(root, "program");
    await writeFile(path, image("strcpy", "system", "gets"));
    const result = await inspect(path, { max_matches: 1 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a match budget refusal");
    expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
    const projected = projectAnalysisError(result.error);
    expect(projected.code).toBe("resource_constraint");
    expect(projected.retryable).toBe(false);
    expect(projected.remediation.action).toContain("max_matches");
  });

  it("keeps a caller file-size budget distinct from host memory", async () => {
    const root = await createTestTempDirectory(
      "rea-risk-signatures-file-budget-",
    );
    const path = join(root, "program");
    await writeFile(path, image("strcpy"));
    const result = await inspect(path, { max_file_bytes: 64 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("Expected a file-size refusal");
    expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
    if (!(result.error instanceof AnalysisResourceConstraintError))
      throw result.error;
    expect(result.error.resource).toBe("file-size");
    expect(projectAnalysisError(result.error).remediation.action).toContain(
      "max_file_bytes",
    );
  });

  it("rejects bytes that are not a supported native container", async () => {
    const root = await createTestTempDirectory("rea-risk-signatures-invalid-");
    const path = join(root, "program");
    await writeFile(path, Buffer.from("not a native image", "latin1"));
    const result = await inspect(path);
    expect(result.ok).toBe(false);
    if (!result.ok)
      expect(result.error).toBeInstanceOf(AnalysisUnsupportedTargetError);
  });
});
