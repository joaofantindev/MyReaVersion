import { expect, it } from "vitest";

import {
  fridaHookPlanSchema,
  planFridaHooksInputSchema,
} from "../../domain/fridaHookPlan.js";
import { planFridaHooks } from "./FridaHookPlanner.js";

const plan = (targets: unknown) =>
  planFridaHooks(
    planFridaHooksInputSchema.parse({
      targets,
    }),
  );

it("defaults to bounded argument observation without mutation", () => {
  const result = plan([{ module: "libc.so.6", symbol: "strcpy" }]);
  expect(fridaHookPlanSchema.parse(result)).toEqual(result);
  expect(result.targets).toEqual([
    {
      id: "hook_1",
      module: "libc.so.6",
      symbol: "strcpy",
      argument_count: 0,
      read_string_arguments: [],
      max_string_bytes: 256,
      include_return_value: true,
      include_backtrace: false,
      backtrace_depth: 4,
    },
  ]);
  expect(result.script_sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(result.script_bytes).toBe(Buffer.byteLength(result.script, "utf8"));
  expect(result.script).toContain('Module.findGlobalExportByName');
  expect(result.script).toContain("Process.findModuleByName");
  expect(result.script).toContain("Interceptor.attach");
  expect(result.script).toContain("readUtf8String");
  expect(result.script).toContain('event: "ready"');
});

it("emits only observation calls and never mutates target state", () => {
  const result = plan([
    {
      symbol: "read",
      argument_count: 3,
      read_string_arguments: [1],
      include_backtrace: true,
      backtrace_depth: 2,
    },
  ]);
  expect(result.script).not.toMatch(
    /writeUtf8String|writeByteArray|Memory\.write|Interceptor\.replace|retval\s*=|args\[[^\]]+\]\s*=/u,
  );
  expect(result.script).toContain("Thread.backtrace");
  expect(result.limitations).toEqual(
    expect.arrayContaining([
      expect.stringContaining("never changes arguments"),
      expect.stringContaining("not retried"),
    ]),
  );
});

it("serializes caller-provided names as data rather than executable source", () => {
  const symbol = 'x"); throw new Error("injected"); //';
  const result = plan([{ symbol }]);
  expect(result.targets[0]?.symbol).toBe(symbol);
  expect(result.script).toContain(JSON.stringify(symbol, null, 2));
  expect(result.script).not.toContain(`x"); throw new Error("injected"); //\n`);
});

it("rejects string arguments outside the declared argument count", () => {
  expect(
    planFridaHooksInputSchema.safeParse({
      targets: [
        {
          symbol: "strcpy",
          argument_count: 1,
          read_string_arguments: [1],
        },
      ],
    }).success,
  ).toBe(false);
});

it("rejects duplicate string argument indices", () => {
  expect(
    planFridaHooksInputSchema.safeParse({
      targets: [
        {
          symbol: "strcpy",
          argument_count: 2,
          read_string_arguments: [0, 0],
        },
      ],
    }).success,
  ).toBe(false);
});
