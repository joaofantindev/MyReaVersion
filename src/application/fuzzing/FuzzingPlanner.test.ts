import { expect, it } from "vitest";

import {
  fuzzingPlanSchema,
  planFuzzingCampaignInputSchema,
} from "../../domain/native/fuzzingPlan.js";
import { planFuzzingCampaign } from "./FuzzingPlanner.js";

const artifact = {
  path: "/artifacts/parser",
  sha256: "a".repeat(64),
  bytes: 4096,
};

const plan = (input: unknown, identity = artifact) =>
  planFuzzingCampaign(planFuzzingCampaignInputSchema.parse(input), identity);

const required = {
  path: artifact.path,
  corpus_directory: "/artifacts/seeds",
  output_directory: "/artifacts/fuzz-output",
};

it("normalizes defaults and emits an inert AFL++ plan", () => {
  const result = plan(required);
  expect(fuzzingPlanSchema.parse(result)).toEqual(result);
  expect(result).toMatchObject({
    plan_version: 1,
    artifact,
    runtime: {
      python: "3",
      engine: "afl++",
      command_environment: "REA_AFL_FUZZ_COMMAND",
      target_arguments: [],
    },
    campaign: {
      corpus_directory: "/artifacts/seeds",
      output_directory: "/artifacts/fuzz-output",
      dictionary_path: null,
    },
    limits: {
      max_runtime_seconds: 300,
      timeout_ms: 1000,
      memory_limit_mb: 512,
    },
  });
  expect(result.script).toContain("import subprocess");
  expect(result.script).toContain("REA_AFL_FUZZ_COMMAND");
  expect(result.script).toContain("file_sha256(TARGET_PATH)");
  expect(result.script).toContain("DICTIONARY_PATH = None");
  expect(result.script).toContain('"-i"');
  expect(result.script).toContain('"-o"');
  expect(result.script).toContain('"-V"');
  expect(result.script).toContain('"AFL_SKIP_CPUFREQ"');
  expect(result.script_sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.script_bytes).toBe(Buffer.byteLength(result.script, "utf8"));
});

it("carries caller arguments, dictionary, and limits into the script", () => {
  const result = plan({
    ...required,
    dictionary_path: "/artifacts/parser.dict",
    target_arguments: ["--input", "@@"],
    max_runtime_seconds: 12,
    timeout_ms: 250,
    memory_limit_mb: 64,
  });
  expect(result.runtime.target_arguments).toEqual(["--input", "@@"]);
  expect(result.campaign.dictionary_path).toBe("/artifacts/parser.dict");
  expect(result.script).toContain("MAX_RUNTIME_SECONDS = 12");
  expect(result.script).toContain("TIMEOUT_MS = 250");
  expect(result.script).toContain("MEMORY_LIMIT_MB = 64");
  expect(result.script).toContain('"--input"');
});

it("serializes caller arguments as data and rejects NUL bytes", () => {
  const argument = '--input"; raise SystemExit("injected"); #';
  const result = plan({
    ...required,
    target_arguments: [argument],
  });
  expect(result.script).toContain(JSON.stringify(argument));
  expect(
    planFuzzingCampaignInputSchema.safeParse({
      ...required,
      target_arguments: ["a\0b"],
    }).success,
  ).toBe(false);
});

it("never emits a shell", () => {
  const result = plan(required);
  expect(result.script).not.toMatch(/shell=True|os\.system|\bexec\(/u);
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("did not execute AFL++"),
      expect.stringContaining("candidate inputs"),
    ]),
  );
});

it("rejects colliding directories and repeated @@ substitutions", () => {
  const invalid = [
    {
      ...required,
      corpus_directory: required.output_directory,
    },
    {
      ...required,
      target_arguments: ["@@", "@@"],
    },
    {
      ...required,
      max_runtime_seconds: 0,
    },
  ];
  for (const value of invalid)
    expect(planFuzzingCampaignInputSchema.safeParse(value).success).toBe(
      false,
    );
});
