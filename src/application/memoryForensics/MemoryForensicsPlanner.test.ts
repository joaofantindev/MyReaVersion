import { expect, it } from "vitest";

import {
  memoryForensicsPlanSchema,
  planMemoryForensicsInputSchema,
} from "../../domain/native/memoryForensicsPlan.js";
import { planMemoryForensics } from "./MemoryForensicsPlanner.js";

const artifact = {
  path: "/artifacts/memory.raw",
  sha256: "a".repeat(64),
  bytes: 4096,
};

const plan = (input: unknown, identity = artifact) =>
  planMemoryForensics(planMemoryForensicsInputSchema.parse(input), identity);

it("normalizes defaults and emits an inert Volatility plan", () => {
  const result = plan({
    path: artifact.path,
    plugins: ["windows.pslist"],
  });
  expect(memoryForensicsPlanSchema.parse(result)).toEqual(result);
  expect(result).toMatchObject({
    plan_version: 1,
    artifact,
    runtime: {
      python: "3",
      engine: "volatility3",
      renderer: "json",
      command_environment: "REA_VOLATILITY_COMMAND",
      plugins: [
        {
          name: "windows.pslist",
          argument_vector: [
            "-r",
            "json",
            "-f",
            artifact.path,
            "windows.pslist",
          ],
        },
      ],
    },
    limits: { timeout_seconds: 300, max_output_bytes: 16777216 },
  });
  expect(result.script).toContain("import subprocess");
  expect(result.script).toContain("REA_VOLATILITY_COMMAND");
  expect(result.script).toContain("file_sha256(IMAGE_PATH)");
  expect(result.script).toContain('"-r", "json", "-f", IMAGE_PATH, plugin');
  expect(result.script_sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.script_bytes).toBe(Buffer.byteLength(result.script, "utf8"));
});

it("carries every selected plugin and limit into the script", () => {
  const result = plan({
    path: artifact.path,
    plugins: ["windows.pslist", "windows.cmdline", "linux.bash"],
    timeout_seconds: 12,
    max_output_bytes: 131072,
  });
  expect(result.runtime.plugins.map(({ name }) => name)).toEqual([
    "windows.pslist",
    "windows.cmdline",
    "linux.bash",
  ]);
  expect(result.script).toContain("TIMEOUT_SECONDS = 12");
  expect(result.script).toContain("MAX_OUTPUT_BYTES = 131072");
});

it("serializes caller plugin names as data and rejects unsafe names", () => {
  const plugin = 'windows.pslist"); raise SystemExit("injected"); #';
  const result = plan({
    path: artifact.path,
    plugins: ["windows.pslist"],
  });
  expect(result.script).toContain(JSON.stringify("windows.pslist"));
  expect(
    planMemoryForensicsInputSchema.safeParse({
      path: artifact.path,
      plugins: [plugin],
    }).success,
  ).toBe(false);
});

it("never emits a shell or writes files", () => {
  const result = plan({
    path: artifact.path,
    plugins: ["windows.pslist"],
  });
  expect(result.script).not.toMatch(
    /shell=True|os\.system|\bexec\(|open\([^)]*,\s*["']w/u,
  );
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("did not execute Volatility"),
      expect.stringContaining("caller-supplied"),
    ]),
  );
});

it("rejects duplicate plugins and plugin names with unsafe punctuation", () => {
  const invalid = [
    {
      path: artifact.path,
      plugins: ["windows.pslist", "windows.pslist"],
    },
    { path: artifact.path, plugins: ["Windows.Pslist"] },
    { path: artifact.path, plugins: ["../evil"] },
    { path: artifact.path, plugins: [] },
  ];
  for (const value of invalid)
    expect(planMemoryForensicsInputSchema.safeParse(value).success).toBe(
      false,
    );
});
