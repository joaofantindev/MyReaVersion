import { z } from "zod";

import { digestSchema } from "./digests.js";

const uint = z.number().int().min(0).max(0xffffffff);

const symbolNameSchema = z
  .string()
  .min(1)
  .max(512)
  .refine((value) => !value.includes("\0"), "Symbol names cannot contain NUL");

const argumentIndexSchema = z.number().int().min(0).max(15);

/** One exported function to observe through a generated Frida hook. */
export const fridaHookTargetInputSchema = z
  .strictObject({
    module: z
      .string()
      .min(1)
      .max(512)
      .optional()
      .describe(
        "Loaded module name, for example libc.so. Omit to search global exports",
      ),
    symbol: symbolNameSchema.describe(
      "Exported function or symbol name resolved at script load",
    ),
    argument_count: z
      .number()
      .int()
      .min(0)
      .max(16)
      .default(0)
      .describe("Number of positional arguments to report (0..16)"),
    read_string_arguments: z
      .array(argumentIndexSchema)
      .max(16)
      .default([])
      .describe(
        "Argument indices to read as a bounded UTF-8 string; each must be less than argument_count",
      ),
    max_string_bytes: z
      .number()
      .int()
      .min(16)
      .max(4096)
      .default(256)
      .describe("Maximum bytes read for each selected string argument"),
    include_return_value: z
      .boolean()
      .default(true)
      .describe("Report the raw return value on function exit"),
    include_backtrace: z
      .boolean()
      .default(false)
      .describe("Report a bounded native backtrace on entry"),
    backtrace_depth: z
      .number()
      .int()
      .min(1)
      .max(16)
      .default(4)
      .describe("Maximum frames retained when include_backtrace is true"),
  })
  .superRefine((target, context) => {
    const seen = new Set<number>();
    for (const index of target.read_string_arguments) {
      if (index >= target.argument_count)
        context.addIssue({
          code: "custom",
          path: ["read_string_arguments"],
          message:
            "Each string argument index must be less than argument_count",
        });
      if (seen.has(index))
        context.addIssue({
          code: "custom",
          path: ["read_string_arguments"],
          message: "String argument indices must be unique",
        });
      seen.add(index);
    }
  });

export const planFridaHooksInputSchema = z.strictObject({
  targets: z
    .array(fridaHookTargetInputSchema)
    .min(1)
    .max(64)
    .describe("Ordered exported functions to observe"),
});

const plannedTargetSchema = z.strictObject({
  id: z.string().regex(/^hook_[1-9][0-9]*$/u),
  module: z.string().nullable(),
  symbol: z.string().min(1),
  argument_count: z.number().int().min(0).max(16),
  read_string_arguments: z.array(argumentIndexSchema).max(16),
  max_string_bytes: z.number().int().min(16).max(4096),
  include_return_value: z.boolean(),
  include_backtrace: z.boolean(),
  backtrace_depth: z.number().int().min(1).max(16),
});

/** An execution-free Frida 17 observation script and its normalized targets. */
export const fridaHookPlanSchema = z.strictObject({
  plan_version: z.literal(1),
  targets: z.array(plannedTargetSchema),
  script: z.string().min(1),
  script_sha256: digestSchema,
  script_bytes: uint,
  runtime: z.strictObject({
    frida_major: z.literal(17),
    target_resolution: z.literal("global-export-or-module-instance"),
  }),
  limitations: z.array(z.string().min(1)),
});

export type PlanFridaHooksInput = z.infer<typeof planFridaHooksInputSchema>;
export type FridaHookPlan = z.infer<typeof fridaHookPlanSchema>;
