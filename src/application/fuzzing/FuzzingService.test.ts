import { expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { NATIVE_FUZZING_PROVIDER } from "../../domain/investigationProviders.js";
import {
  planFuzzingCampaignInputSchema,
  type FuzzingPlan,
} from "../../domain/native/fuzzingPlan.js";
import { ok } from "../../domain/result.js";
import { planFuzzingCampaign } from "./FuzzingPlanner.js";
import { FuzzingService } from "./FuzzingService.js";

const identity = NATIVE_FUZZING_PROVIDER;

const artifact = {
  path: "/artifacts/parser",
  sha256: "a".repeat(64),
  bytes: 512,
};

const input = planFuzzingCampaignInputSchema.parse({
  path: artifact.path,
  corpus_directory: "/artifacts/seeds",
  output_directory: "/artifacts/fuzz-output",
});

const plan = (overrides: Partial<FuzzingPlan> = {}) => ({
  ...planFuzzingCampaign(input, artifact),
  ...overrides,
});

const serviceWith = (value: FuzzingPlan) =>
  new FuzzingService({
    identity,
    plan: () => Promise.resolve(ok(value)),
  });

it("rejects relative paths and extra arguments before planning", async () => {
  let calls = 0;
  const service = new FuzzingService({
    identity,
    plan: () => {
      calls += 1;
      return Promise.resolve(ok(plan()));
    },
  });
  const relative = await service.plan({ ...input, path: "parser" });
  const relativeCorpus = await service.plan({
    ...input,
    corpus_directory: "seeds",
  });
  const extra = await service.plan({ ...input, extra: true });
  expect(relative.ok).toBe(false);
  expect(relativeCorpus.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!relativeCorpus.ok)
    expect(relativeCorpus.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records identity-bound derived Evidence for the selected target", async () => {
  const result = await serviceWith(plan()).plan(input);
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "derived",
    subject: { format: "file" },
    normalized_result: {
      artifact,
      campaign: { output_directory: "/artifacts/fuzz-output" },
    },
  });
  expect(result.value.locations).toContainEqual({
    kind: "artifact-path",
    path: artifact.path,
  });
});

it("rejects changed campaign fields, limits, or script identity", async () => {
  const cases: readonly FuzzingPlan[] = [
    {
      ...plan(),
      campaign: { ...plan().campaign, output_directory: "/artifacts/other" },
    },
    {
      ...plan(),
      limits: { ...plan().limits, max_runtime_seconds: 1 },
    },
    {
      ...plan(),
      script_sha256: "b".repeat(64),
    },
    {
      ...plan(),
      script_bytes: 1,
    },
    {
      ...plan(),
      artifact: { ...artifact, path: "/artifacts/other" },
    },
  ];
  for (const value of cases) {
    const result = await serviceWith(value).plan(input);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisOutputError);
  }
});

it("discards a plan if the caller cancels while the provider completes", async () => {
  const controller = new AbortController();
  const service = new FuzzingService({
    identity,
    plan: () => {
      controller.abort();
      return Promise.resolve(ok(plan()));
    },
  });
  const result = await service.plan(input, { signal: controller.signal });
  expect(result.ok).toBe(false);
  if (!result.ok) expect(result.error).toBeInstanceOf(AnalysisCancelledError);
});

it("rejects a runtime above the schema maximum", () => {
  const parsed = planFuzzingCampaignInputSchema.safeParse({
    ...input,
    max_runtime_seconds: 86401,
  });
  expect(parsed.success).toBe(false);
});
