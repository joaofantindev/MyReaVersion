import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected target read used for identity. */
export const MAX_PLAN_FUZZING_FILE_BYTES = 536870912;

const targetArgumentSchema = z
  .string()
  .min(1)
  .max(1024)
  .refine((value) => !value.includes("\0"), {
    message: "Target arguments cannot contain NUL",
  });

export const planFuzzingCampaignInputSchema = z
  .strictObject({
    path: localPathStringSchema.describe(
      "Absolute filesystem path to the fuzz target",
    ),
    corpus_directory: localPathStringSchema.describe(
      "Absolute path to the existing seed corpus directory",
    ),
    output_directory: localPathStringSchema.describe(
      "Absolute path where AFL++ writes queues, crashes, and hangs",
    ),
    dictionary_path: localPathStringSchema
      .optional()
      .describe("Optional absolute path to an AFL dictionary file"),
    target_arguments: z
      .array(targetArgumentSchema)
      .max(32)
      .default([])
      .describe(
        'Target argv entries after the target path; include "@@" where AFL++ should substitute the input file',
      ),
    max_runtime_seconds: z
      .number()
      .int()
      .min(1)
      .max(86400)
      .default(300)
      .describe("AFL++ -V campaign deadline in the generated script"),
    timeout_ms: z
      .number()
      .int()
      .min(1)
      .max(600000)
      .default(1000)
      .describe("AFL++ per-execution timeout in milliseconds"),
    memory_limit_mb: z
      .number()
      .int()
      .min(1)
      .max(65536)
      .default(512)
      .describe("AFL++ -m target memory limit in MiB"),
    max_file_bytes: z
      .number()
      .int()
      .min(64)
      .max(MAX_PLAN_FUZZING_FILE_BYTES)
      .default(67108864)
      .describe("Maximum stable target bytes read for identity"),
  })
  .superRefine((input, context) => {
    if (input.corpus_directory === input.output_directory)
      context.addIssue({
        code: "custom",
        path: ["output_directory"],
        message: "Corpus and output directories must differ",
      });
    const substitutions = input.target_arguments.filter(
      (argument) => argument === "@@",
    ).length;
    if (substitutions > 1)
      context.addIssue({
        code: "custom",
        path: ["target_arguments"],
        message: "At most one target argument may be exactly @@",
      });
  });

/** One inert AFL++ campaign and the fuzz-target identity it targets. */
export const fuzzingPlanSchema = z.strictObject({
  plan_version: z.literal(1),
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  runtime: z.strictObject({
    python: z.literal("3"),
    engine: z.literal("afl++"),
    command_environment: z.literal("REA_AFL_FUZZ_COMMAND"),
    target_arguments: z.array(targetArgumentSchema),
  }),
  campaign: z.strictObject({
    corpus_directory: z.string().min(1),
    output_directory: z.string().min(1),
    dictionary_path: z.string().min(1).nullable(),
  }),
  limits: z.strictObject({
    max_runtime_seconds: z.number().int().min(1).max(86400),
    timeout_ms: z.number().int().min(1).max(600000),
    memory_limit_mb: z.number().int().min(1).max(65536),
  }),
  script: z.string().min(1),
  script_sha256: digestSchema,
  script_bytes: uint,
  limitations: z.array(z.string().min(1)),
});

export type PlanFuzzingCampaignInput = z.infer<
  typeof planFuzzingCampaignInputSchema
>;
export type FuzzingPlan = z.infer<typeof fuzzingPlanSchema>;
