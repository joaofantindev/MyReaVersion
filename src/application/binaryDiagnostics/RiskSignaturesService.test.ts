import { expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import {
  RISK_SIGNATURE_CATEGORIES,
  RISK_SIGNATURE_SEVERITIES,
  type NativeRiskSignatures,
} from "../../domain/native/riskSignatures.js";
import { NATIVE_RISK_SIGNATURES_PROVIDER } from "../../domain/investigationProviders.js";
import { ok } from "../../domain/result.js";
import { RiskSignaturesService } from "./RiskSignaturesService.js";

const identity = NATIVE_RISK_SIGNATURES_PROVIDER;

const report: NativeRiskSignatures = {
  artifact: {
    path: "/artifacts/app",
    sha256: "a".repeat(64),
    bytes: 512,
  },
  format: "elf",
  bits: 64,
  architecture: "x86_64",
  byte_order: "little",
  sections: [],
  matches: [],
  summary: {
    matches: 0,
    by_category: RISK_SIGNATURE_CATEGORIES.map((category) => ({
      category,
      count: 0,
    })),
    by_severity: RISK_SIGNATURE_SEVERITIES.map((severity) => ({
      severity,
      count: 0,
    })),
  },
  coverage: {
    status: "complete",
    reason: null,
    bytes_scanned: 512,
    strings_examined: 0,
    matches_examined: 0,
    truncated_strings: 0,
  },
  limitations: ["Static byte observation only."],
};

const serviceWith = (value: NativeRiskSignatures) =>
  new RiskSignaturesService({
    identity,
    inspect: () => Promise.resolve(ok(value)),
  });

it("rejects a relative path and extra arguments before reading", async () => {
  let calls = 0;
  const service = new RiskSignaturesService({
    identity,
    inspect: () => {
      calls += 1;
      return Promise.resolve(ok(report));
    },
  });
  const relative = await service.inspect({ path: "app" });
  const extra = await service.inspect({
    path: report.artifact.path,
    extra: true,
  });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records the selected native image and its summary", async () => {
  const result = await serviceWith(report).inspect({
    path: report.artifact.path,
  });
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "observed",
    subject: { format: "elf", architecture: "x86_64" },
    normalized_result: report,
  });
  expect(result.value.locations).toContainEqual({
    kind: "artifact-path",
    path: report.artifact.path,
  });
});
it("uses the canonical Mach-O evidence format", async () => {
  const result = await serviceWith({ ...report, format: "macho" }).inspect({
    path: report.artifact.path,
  });
  if (!result.ok) throw result.error;
  expect(result.value.subject).toMatchObject({ format: "mach-o" });
});

it("rejects a provider that changes the artifact path", async () => {
  const result = await serviceWith({
    ...report,
    artifact: { ...report.artifact, path: "/artifacts/other" },
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("rejects inconsistent summary or coverage counts", async () => {
  const cases: readonly NativeRiskSignatures[] = [
    {
      ...report,
      summary: {
        ...report.summary,
        matches: 1,
      },
    },
    {
      ...report,
      coverage: {
        ...report.coverage,
        truncated_strings: 1,
      },
    },
    {
      ...report,
      coverage: {
        ...report.coverage,
        bytes_scanned: 511,
      },
    },
  ];
  for (const value of cases) {
    const result = await serviceWith(value).inspect({
      path: report.artifact.path,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
  }
});

it("rejects a match outside the admitted artifact bytes", async () => {
  const result = await serviceWith({
    ...report,
    matches: [
      {
        rule_id: "unsafe.strcpy",
        category: "unsafe_memory",
        severity: "high",
        title: "Unbounded string copy",
        annotation: "Verify the destination capacity.",
        match_kind: "symbol",
        encoding: "ascii",
        offset: 500,
        bytes: 64,
        section: null,
        value: "strcpy",
        preview: "strcpy",
        redacted: false,
        value_sha256: "b".repeat(64),
      },
    ],
    summary: {
      ...report.summary,
      matches: 1,
      by_category: report.summary.by_category.map((row) =>
        row.category === "unsafe_memory" ? { ...row, count: 1 } : row,
      ),
      by_severity: report.summary.by_severity.map((row) =>
        row.severity === "high" ? { ...row, count: 1 } : row,
      ),
    },
    coverage: { ...report.coverage, matches_examined: 1 },
  }).inspect({ path: report.artifact.path });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
});

it("discards an observation if the caller cancels while the provider completes", async () => {
  const controller = new AbortController();
  const service = new RiskSignaturesService({
    identity,
    inspect: () => {
      controller.abort();
      return Promise.resolve(ok(report));
    },
  });
  const result = await service.inspect(
    { path: report.artifact.path },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});
