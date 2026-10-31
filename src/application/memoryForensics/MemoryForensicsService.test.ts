import { expect, it } from "vitest";

import {
  AnalysisCancelledError,
  AnalysisInputError,
  AnalysisOutputError,
} from "../../domain/analysisErrorCore.js";
import { NATIVE_MEMORY_FORENSICS_PROVIDER } from "../../domain/investigationProviders.js";
import {
  planMemoryForensicsInputSchema,
  type MemoryForensicsPlan,
} from "../../domain/native/memoryForensicsPlan.js";
import { ok } from "../../domain/result.js";
import { planMemoryForensics } from "./MemoryForensicsPlanner.js";
import { MemoryForensicsService } from "./MemoryForensicsService.js";

const identity = NATIVE_MEMORY_FORENSICS_PROVIDER;

const artifact = {
  path: "/artifacts/memory.raw",
  sha256: "a".repeat(64),
  bytes: 512,
};

const input = planMemoryForensicsInputSchema.parse({
  path: artifact.path,
  plugins: ["windows.pslist"],
});

const plan = (overrides: Partial<MemoryForensicsPlan> = {}) => ({
  ...planMemoryForensics(input, artifact),
  ...overrides,
});

const serviceWith = (value: MemoryForensicsPlan) =>
  new MemoryForensicsService({
    identity,
    plan: () => Promise.resolve(ok(value)),
  });

it("rejects a relative path and extra arguments before planning", async () => {
  let calls = 0;
  const service = new MemoryForensicsService({
    identity,
    plan: () => {
      calls += 1;
      return Promise.resolve(ok(plan()));
    },
  });
  const relative = await service.plan({ ...input, path: "memory.raw" });
  const extra = await service.plan({ ...input, extra: true });
  expect(relative.ok).toBe(false);
  expect(extra.ok).toBe(false);
  if (!relative.ok) expect(relative.error).toBeInstanceOf(AnalysisInputError);
  if (!extra.ok) expect(extra.error).toBeInstanceOf(AnalysisInputError);
  expect(calls).toBe(0);
});

it("records identity-bound derived Evidence for the selected image", async () => {
  const result = await serviceWith(plan()).plan(input);
  expect(result.ok).toBe(true);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    confidence: "derived",
    subject: { format: "file" },
    normalized_result: {
      artifact,
      runtime: { plugins: [{ name: "windows.pslist" }] },
    },
  });
  expect(result.value.locations).toContainEqual({
    kind: "artifact-path",
    path: artifact.path,
  });
});

it("rejects changed plugins, limits, or script identity", async () => {
  const cases: readonly MemoryForensicsPlan[] = [
    {
      ...plan(),
      runtime: {
        ...plan().runtime,
        plugins: [
          { name: "windows.cmdline", argument_vector: ["windows.cmdline"] },
        ],
      },
    },
    {
      ...plan(),
      limits: { ...plan().limits, timeout_seconds: 1 },
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
  const service = new MemoryForensicsService({
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

it("rejects an output budget below the schema minimum", () => {
  const parsed = planMemoryForensicsInputSchema.safeParse({
    ...input,
    max_output_bytes: 1,
  });
  expect(parsed.success).toBe(false);
});
