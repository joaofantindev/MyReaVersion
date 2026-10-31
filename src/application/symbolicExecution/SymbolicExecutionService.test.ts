import { expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { NATIVE_SYMBOLIC_EXECUTION_PROVIDER } from "../../domain/investigationProviders.js";
import {
  planSymbolicExecutionInputSchema,
  type SymbolicExecutionPlan,
} from "../../domain/native/symbolicExecutionPlan.js";
import { ok } from "../../domain/result.js";
import { planSymbolicExecution } from "./SymbolicExecutionPlanner.js";
import { SymbolicExecutionService } from "./SymbolicExecutionService.js";

const identity = NATIVE_SYMBOLIC_EXECUTION_PROVIDER;

const artifact = {
  path: "/artifacts/program",
  sha256: "a".repeat(64),
  bytes: 512,
};

const input = planSymbolicExecutionInputSchema.parse({
  path: artifact.path,
  find: [{ kind: "symbol", value: "win" }],
});

const plan = (overrides: Partial<SymbolicExecutionPlan> = {}) => ({
  ...planSymbolicExecution(input, artifact),
  ...overrides,
});

const serviceWith = (value: SymbolicExecutionPlan) =>
  new SymbolicExecutionService({
    identity,
    plan: () => Promise.resolve(ok(value)),
  });

it("rejects a relative path and extra arguments before planning", async () => {
  let calls = 0;
  const service = new SymbolicExecutionService({
    identity,
    plan: () => {
      calls += 1;
      return Promise.resolve(ok(plan()));
    },
  });
  const relative = await service.plan({ ...input, path: "program" });
  const extra = await service.plan({ ...input, extra: true });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records identity-bound derived Evidence for the selected file", async () => {
  const result = await serviceWith(plan()).plan(input);
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "derived",
    subject: { format: "file" },
    normalized_result: {
      artifact,
      find: [{ kind: "symbol", value: "win" }],
    },
  });
  expect(result.value.locations).toContainEqual({
    kind: "artifact-path",
    path: artifact.path,
  });
});

it("rejects changed targets, limits, or script identity", async () => {
  const cases: readonly SymbolicExecutionPlan[] = [
    {
      ...plan(),
      find: [{ kind: "symbol", value: "other" }],
    },
    {
      ...plan(),
      limits: { ...plan().limits, max_steps: 1 },
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
  const service = new SymbolicExecutionService({
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

it("rejects a symbolic argument count above the schema maximum", () => {
  const parsed = planSymbolicExecutionInputSchema.safeParse({
    ...input,
    symbolic_arguments: 9,
  });
  expect(parsed.success).toBe(false);
});
