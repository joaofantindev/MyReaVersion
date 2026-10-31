import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected artifact read used for identity. */
export const MAX_PLAN_SYMBOLIC_EXECUTION_FILE_BYTES = 536870912;

const addressPattern = /^0x[0-9a-fA-F]{1,16}$/u;
const validSymbol = (value: string): boolean => !value.includes("\0");

/** One entry, find, or avoid location resolved inside the generated script. */
export const symbolicTargetSchema = z.strictObject({
  kind: z
    .enum(["address", "symbol"])
    .describe("Resolve the value as a linked address or a loader symbol"),
  value: z
    .string()
    .min(1)
    .max(512)
    .describe(
      'Hexadecimal address such as "0x401136" for kind address, or an exact symbol name for kind symbol',
    ),
});

export const planSymbolicExecutionInputSchema = z
  .strictObject({
    path: localPathStringSchema.describe(
      "Absolute filesystem path to the binary the generated plan targets",
    ),
    find: z
      .array(symbolicTargetSchema)
      .min(1)
      .max(8)
      .describe("Addresses or symbols that make a path interesting"),
    avoid: z
      .array(symbolicTargetSchema)
      .max(16)
      .default([])
      .describe("Addresses or symbols that a retained path must not reach"),
    entry: symbolicTargetSchema
      .optional()
      .describe(
        "Starting address or symbol; omit to use the image entry point through entry_state",
      ),
    symbolic_arguments: z
      .number()
      .int()
      .min(0)
      .max(8)
      .default(0)
      .describe(
        "Number of positional argv entries to treat as symbolic bytes (0..8)",
      ),
    max_symbolic_argument_bytes: z
      .number()
      .int()
      .min(8)
      .max(4096)
      .default(64)
      .describe("Byte length of each symbolic argument"),
    max_steps: z
      .number()
      .int()
      .min(1)
      .max(100000)
      .default(1000)
      .describe("Maximum simulation-manager steps in the generated script"),
    deadline_seconds: z
      .number()
      .int()
      .min(1)
      .max(600)
      .default(60)
      .describe("Wall-clock deadline checked between generated-script steps"),
    max_solution_bytes: z
      .number()
      .int()
      .min(1)
      .max(4096)
      .default(256)
      .describe("Maximum bytes retained for each solved symbolic argument"),
    max_file_bytes: z
      .number()
      .int()
      .min(64)
      .max(MAX_PLAN_SYMBOLIC_EXECUTION_FILE_BYTES)
      .default(67108864)
      .describe(
        "Maximum stable artifact bytes read for identity (the script itself reads the original path)",
      ),
  })
  .superRefine((input, context) => {
    const key = (target: z.infer<typeof symbolicTargetSchema>) =>
      `${target.kind}:${target.value}`;
    const seenFind = new Set<string>();
    for (const target of input.find) {
      if (target.kind === "address" && !addressPattern.test(target.value))
        context.addIssue({
          code: "custom",
          path: ["find"],
          message: 'Address targets must use "0x" followed by hexadecimal digits',
        });
      if (target.kind === "symbol" && !validSymbol(target.value))
        context.addIssue({
          code: "custom",
          path: ["find"],
          message: "Symbol targets must be non-empty and cannot contain NUL",
        });
      if (seenFind.has(key(target)))
        context.addIssue({
          code: "custom",
          path: ["find"],
          message: "Find targets must be unique",
        });
      seenFind.add(key(target));
    }
    const avoidKeys = new Set<string>();
    for (const target of input.avoid) {
      if (target.kind === "address" && !addressPattern.test(target.value))
        context.addIssue({
          code: "custom",
          path: ["avoid"],
          message: 'Address targets must use "0x" followed by hexadecimal digits',
        });
      if (target.kind === "symbol" && !validSymbol(target.value))
        context.addIssue({
          code: "custom",
          path: ["avoid"],
          message: "Symbol targets must be non-empty and cannot contain NUL",
        });
      if (avoidKeys.has(key(target)))
        context.addIssue({
          code: "custom",
          path: ["avoid"],
          message: "Avoid targets must be unique",
        });
      if (seenFind.has(key(target)))
        context.addIssue({
          code: "custom",
          path: ["avoid"],
          message: "A target cannot appear in both find and avoid",
        });
      avoidKeys.add(key(target));
    }
    if (input.entry !== undefined) {
      if (
        input.entry.kind === "address" &&
        !addressPattern.test(input.entry.value)
      )
        context.addIssue({
          code: "custom",
          path: ["entry"],
          message: 'Address targets must use "0x" followed by hexadecimal digits',
        });
      if (
        input.entry.kind === "symbol" &&
        !validSymbol(input.entry.value)
      )
        context.addIssue({
          code: "custom",
          path: ["entry"],
          message: "Symbol targets must be non-empty and cannot contain NUL",
        });
      if (
        input.find.some(
          (target) =>
            target.kind === input.entry?.kind &&
            target.value === input.entry?.value,
        )
      )
        context.addIssue({
          code: "custom",
          path: ["entry"],
          message: "The entry target cannot also be a find target",
        });
    }
  });

const plannedTargetSchema = z.strictObject({
  kind: z.enum(["address", "symbol"]),
  value: z.string().min(1),
});

/** One inert angr plan and the artifact identity it was generated for. */
export const symbolicExecutionPlanSchema = z.strictObject({
  plan_version: z.literal(1),
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  runtime: z.strictObject({
    python: z.literal("3"),
    engine: z.literal("angr"),
    api: z.literal("project-simulation-manager"),
    shared_libraries: z.literal("disabled"),
  }),
  entry: plannedTargetSchema.nullable(),
  find: z.array(plannedTargetSchema).min(1),
  avoid: z.array(plannedTargetSchema),
  limits: z.strictObject({
    max_steps: z.number().int().min(1).max(100000),
    deadline_seconds: z.number().int().min(1).max(600),
    symbolic_arguments: z.number().int().min(0).max(8),
    max_symbolic_argument_bytes: z.number().int().min(8).max(4096),
    max_solution_bytes: z.number().int().min(1).max(4096),
  }),
  script: z.string().min(1),
  script_sha256: digestSchema,
  script_bytes: uint,
  limitations: z.array(z.string().min(1)),
});

export type PlanSymbolicExecutionInput = z.infer<
  typeof planSymbolicExecutionInputSchema
>;
export type SymbolicTarget = z.infer<typeof symbolicTargetSchema>;
export type SymbolicExecutionPlan = z.infer<
  typeof symbolicExecutionPlanSchema
>;
