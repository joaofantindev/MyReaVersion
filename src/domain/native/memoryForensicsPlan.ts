import { z } from "zod";

import { digestSchema } from "../digests.js";
import { localPathStringSchema } from "../localPath.js";

const uint = z.number().int().min(0).max(0xffffffff);

/** Hard ceiling on the caller-selected memory-image read used for identity. */
export const MAX_PLAN_MEMORY_FORENSICS_FILE_BYTES = 536870912;

const pluginPattern = /^[a-z][a-z0-9_.]{0,127}$/u;

/** One bounded Volatility 3 plugin selection. */
export const memoryForensicsPluginSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(
    pluginPattern,
    'Plugin names start with a lowercase letter and contain only lowercase letters, digits, underscores, and dots',
  );

export const planMemoryForensicsInputSchema = z.strictObject({
  path: localPathStringSchema.describe(
    "Absolute filesystem path to the memory image the generated plan targets",
  ),
  plugins: z
    .array(memoryForensicsPluginSchema)
    .min(1)
    .max(16)
    .describe(
      "Volatility 3 plugin names such as windows.pslist, windows.cmdline, or linux.bash",
    ),
  timeout_seconds: z
    .number()
    .int()
    .min(1)
    .max(3600)
    .default(300)
    .describe("Per-plugin wall-clock deadline in the generated script"),
  max_output_bytes: z
    .number()
    .int()
    .min(65536)
    .max(67108864)
    .default(16777216)
    .describe(
      "Maximum retained stdout bytes and stderr bytes per plugin in the generated script",
    ),
  max_file_bytes: z
    .number()
    .int()
    .min(64)
    .max(MAX_PLAN_MEMORY_FORENSICS_FILE_BYTES)
    .default(67108864)
    .describe("Maximum stable memory-image bytes read for identity"),
}).superRefine((input, context) => {
  const seen = new Set<string>();
  for (const plugin of input.plugins) {
    if (seen.has(plugin))
      context.addIssue({
        code: "custom",
        path: ["plugins"],
        message: "Plugin names must be unique",
      });
    seen.add(plugin);
  }
});

const plannedPluginSchema = z.strictObject({
  name: memoryForensicsPluginSchema,
  argument_vector: z.array(z.string().min(1)),
});

/** One inert Volatility plan and the memory-image identity it targets. */
export const memoryForensicsPlanSchema = z.strictObject({
  plan_version: z.literal(1),
  artifact: z.strictObject({
    path: z.string().min(1),
    sha256: digestSchema,
    bytes: uint,
  }),
  runtime: z.strictObject({
    python: z.literal("3"),
    engine: z.literal("volatility3"),
    renderer: z.literal("json"),
    command_environment: z.literal("REA_VOLATILITY_COMMAND"),
    plugins: z.array(plannedPluginSchema).min(1),
  }),
  limits: z.strictObject({
    timeout_seconds: z.number().int().min(1).max(3600),
    max_output_bytes: z.number().int().min(65536).max(67108864),
  }),
  script: z.string().min(1),
  script_sha256: digestSchema,
  script_bytes: uint,
  limitations: z.array(z.string().min(1)),
});

export type PlanMemoryForensicsInput = z.infer<
  typeof planMemoryForensicsInputSchema
>;
export type MemoryForensicsPlan = z.infer<typeof memoryForensicsPlanSchema>;
