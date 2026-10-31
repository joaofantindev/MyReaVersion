import { expect, it } from "vitest";

import {
  planSymbolicExecutionInputSchema,
  symbolicExecutionPlanSchema,
} from "../../domain/native/symbolicExecutionPlan.js";
import { planSymbolicExecution } from "./SymbolicExecutionPlanner.js";

const artifact = {
  path: "/artifacts/program",
  sha256: "a".repeat(64),
  bytes: 4096,
};

const plan = (input: unknown, identity = artifact) =>
  planSymbolicExecution(
    planSymbolicExecutionInputSchema.parse(input),
    identity,
  );

it("normalizes defaults and emits an inert angr search plan", () => {
  const result = plan({
    path: artifact.path,
    find: [{ kind: "symbol", value: "win" }],
  });
  expect(symbolicExecutionPlanSchema.parse(result)).toEqual(result);
  expect(result).toMatchObject({
    plan_version: 1,
    artifact,
    runtime: {
      python: "3",
      engine: "angr",
      api: "project-simulation-manager",
      shared_libraries: "disabled",
    },
    entry: null,
    find: [{ kind: "symbol", value: "win" }],
    avoid: [],
    limits: {
      max_steps: 1000,
      deadline_seconds: 60,
      symbolic_arguments: 0,
      max_symbolic_argument_bytes: 64,
      max_solution_bytes: 256,
    },
  });
  expect(result.script).toContain("import angr");
  expect(result.script).toContain("auto_load_libs=False");
  expect(result.script).toContain("project.loader.find_symbol");
  expect(result.script).toContain("project.factory.entry_state");
  expect(result.script).toContain("find=find, avoid=avoid");
  expect(result.script).toContain("simgr.step()");
  expect(result.script).toContain("ENTRY = None");
  expect(result.script).toContain("file_sha256(PROJECT_PATH)");
  expect(result.script_sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.script_bytes).toBe(Buffer.byteLength(result.script, "utf8"));
});

it("carries caller targets and symbolic argument bounds into the script", () => {
  const result = plan({
    path: artifact.path,
    entry: { kind: "address", value: "0x401000" },
    find: [{ kind: "address", value: "0x401136" }],
    avoid: [{ kind: "symbol", value: "fail" }],
    symbolic_arguments: 2,
    max_symbolic_argument_bytes: 128,
    max_steps: 25,
    deadline_seconds: 5,
    max_solution_bytes: 32,
  });
  expect(result.entry).toEqual({ kind: "address", value: "0x401000" });
  expect(result.script).toContain('"0x401136"');
  expect(result.script).toContain('"fail"');
  expect(result.script).toContain("MAX_STEPS = 25");
  expect(result.script).toContain("DEADLINE_SECONDS = 5");
  expect(result.script).toContain("SYMBOLIC_ARGUMENTS = 2");
  expect(result.script).toContain("MAX_ARGUMENT_BYTES = 128");
  expect(result.script).toContain("MAX_SOLUTION_BYTES = 32");
  expect(result.script).toContain('"kind": "address"');
});

it("serializes caller names as data rather than executable Python", () => {
  const symbol = 'x"); raise SystemExit("injected"); #';
  const result = plan({
    path: artifact.path,
    find: [{ kind: "symbol", value: symbol }],
  });
  expect(result.find[0]?.value).toBe(symbol);
  expect(result.script).toContain(JSON.stringify(symbol));
});

it("never emits shell, process, or mutation calls", () => {
  const result = plan({
    path: artifact.path,
    find: [{ kind: "symbol", value: "win" }],
  });
  expect(result.script).not.toMatch(
    /subprocess|os\.system|shell=True|\bexec\(|writeFile|open\([^)]*,\s*["']w/u,
  );
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("did not execute angr"),
      expect.stringContaining("not prove"),
    ]),
  );
});

it("rejects malformed addresses, duplicates, and find/avoid overlap", () => {
  const invalid = [
    {
      path: artifact.path,
      find: [{ kind: "address", value: "401136" }],
    },
    {
      path: artifact.path,
      find: [
        { kind: "symbol", value: "win" },
        { kind: "symbol", value: "win" },
      ],
    },
    {
      path: artifact.path,
      find: [{ kind: "symbol", value: "win" }],
      avoid: [{ kind: "symbol", value: "win" }],
    },
    {
      path: artifact.path,
      find: [{ kind: "symbol", value: "win" }],
      entry: { kind: "symbol", value: "win" },
    },
  ];
  for (const value of invalid)
    expect(planSymbolicExecutionInputSchema.safeParse(value).success).toBe(
      false,
    );
});
