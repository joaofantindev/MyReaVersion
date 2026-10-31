import { describe, expect, it } from "vitest";

import {
  inspectNativeRiskSignaturesInputSchema,
  type InspectNativeRiskSignaturesInput,
} from "../../domain/native/riskSignatures.js";
import {
  elfNoteFixture,
  gnuBuildIdNote,
} from "../elf/ElfNotes.fixture.js";
import { BinaryFormatFailure } from "../metadata/BinaryContainer.js";
import {
  parseNativeRiskSignatures,
  RiskSignatureBudgetFailure,
} from "./RiskSignatureParser.js";

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/app",
  sha256: "a".repeat(64),
  bytes: bytes.length,
});

const input = (
  overrides: Partial<InspectNativeRiskSignaturesInput> = {},
): InspectNativeRiskSignaturesInput =>
  inspectNativeRiskSignaturesInputSchema.parse({
    path: "/artifacts/app",
    ...overrides,
  });

const asciiImage = (...values: readonly string[]): Buffer =>
  elfNoteFixture({
    notes: Buffer.concat([
      gnuBuildIdNote(),
      Buffer.from(values.map((value) => `\0${value}\0`).join(""), "latin1"),
    ]),
  });

const utf16Image = (value: string): Buffer =>
  elfNoteFixture({
    notes: Buffer.concat([
      gnuBuildIdNote(),
      Buffer.from(`\0${value}\0`, "utf16le"),
    ]),
  });

const parse = (
  bytes: Buffer,
  overrides: Partial<InspectNativeRiskSignaturesInput> = {},
) => parseNativeRiskSignatures(bytes, artifact(bytes), input(overrides));

const ruleIds = (bytes: Buffer, overrides = {}) =>
  parse(bytes, overrides).matches.map((match) => match.rule_id);

describe("native risk-signature parsing", () => {
  it("matches whole symbol-like strings and attributes the containing section", () => {
    const bytes = asciiImage("strcpy", "system");
    const report = parse(bytes);
    expect(report.format).toBe("elf");
    expect(report.bits).toBe(64);
    expect(report.byte_order).toBe("little");
    expect(report.coverage).toMatchObject({
      status: "complete",
      reason: null,
      bytes_scanned: bytes.length,
    });
    const match = report.matches.find(
      (candidate) => candidate.rule_id === "unsafe.strcpy",
    );
    expect(match).toMatchObject({
      category: "unsafe_memory",
      severity: "high",
      match_kind: "symbol",
      encoding: "ascii",
      section: ".note.gnu.build-id",
      value: "strcpy",
      preview: "strcpy",
      redacted: false,
    });
    expect(match?.value_sha256).toMatch(/^[a-f0-9]{64}$/u);
    expect(report.summary.matches).toBe(report.matches.length);
    expect(
      report.summary.by_category.reduce((total, row) => total + row.count, 0),
    ).toBe(report.matches.length);
    expect(
      report.summary.by_severity.reduce((total, row) => total + row.count, 0),
    ).toBe(report.matches.length);
  });

  it("normalizes symbol versions and leading underscores", () => {
    const bytes = asciiImage("strcpy@@GLIBC_2.2.5", "_system");
    const report = parse(bytes);
    const byRule = new Map(
      report.matches.map((match) => [match.rule_id, match]),
    );
    expect(byRule.get("unsafe.strcpy")?.value).toBe("strcpy@@GLIBC_2.2.5");
    expect(byRule.get("exec.shell")?.value).toBe("_system");
  });

  it("matches sanitizer symbols by decorated prefix", () => {
    const report = parse(asciiImage("__asan_init", "__ubsan_handle_add_overflow"));
    expect(
      report.matches.find((match) => match.rule_id === "hardening.asan"),
    ).toMatchObject({ match_kind: "symbol", severity: "informational" });
    expect(
      report.matches.find((match) => match.rule_id === "hardening.ubsan"),
    ).toMatchObject({ match_kind: "symbol" });
  });

  it("extracts UTF-16LE runs without also reporting the ASCII fragments", () => {
    const report = parse(utf16Image("strcpy"));
    const matches = report.matches.filter(
      (match) => match.rule_id === "unsafe.strcpy",
    );
    expect(matches).toHaveLength(1);
    expect(matches[0]).toMatchObject({
      encoding: "utf16le",
      match_kind: "symbol",
      value: "strcpy",
    });
  });

  it("keeps a UTF-16LE run that ends at the end of the file", () => {
    const bytes = elfNoteFixture({
      ownership: "program",
      notes: Buffer.concat([
        gnuBuildIdNote(),
        Buffer.from("strcpy", "utf16le"),
      ]),
    });
    const match = parse(bytes).matches.find(
      (candidate) => candidate.rule_id === "unsafe.strcpy",
    );
    expect(match).toMatchObject({
      encoding: "utf16le",
      match_kind: "symbol",
      value: "strcpy",
    });
  });

  it("redacts credential-like patterns while retaining a value digest", () => {
    const bytes = asciiImage("AKIAABCDEFGHIJKLMNOP");
    const match = parse(bytes).matches.find(
      (candidate) => candidate.rule_id === "credential.aws_access_key",
    );
    expect(match).toMatchObject({
      category: "credential_pattern",
      match_kind: "pattern",
      value: null,
      preview: "<redacted>",
      redacted: true,
    });
    expect(match?.value_sha256).toMatch(/^[a-f0-9]{64}$/u);
  });

  it("requires include_text_matches to report API names embedded in prose", () => {
    const bytes = asciiImage("use strcpy carefully");
    expect(ruleIds(bytes)).not.toContain("unsafe.strcpy");
    const match = parse(bytes, { include_text_matches: true }).matches.find(
      (candidate) => candidate.rule_id === "unsafe.strcpy",
    );
    expect(match).toMatchObject({ match_kind: "text", value: "strcpy" });
  });

  it("fails when the string-run budget is exhausted", () => {
    const bytes = asciiImage("strcpy", "system", "gets");
    try {
      parse(bytes, { max_strings: 2 });
      throw new Error("Expected a string budget failure");
    } catch (cause) {
      expect(cause).toBeInstanceOf(RiskSignatureBudgetFailure);
      expect((cause as RiskSignatureBudgetFailure).kind).toBe("strings");
    }
  });

  it("fails when the retained-match budget is exhausted", () => {
    const bytes = asciiImage("strcpy", "system", "gets");
    try {
      parse(bytes, { max_matches: 1 });
      throw new Error("Expected a match budget failure");
    } catch (cause) {
      expect(cause).toBeInstanceOf(RiskSignatureBudgetFailure);
      expect((cause as RiskSignatureBudgetFailure).kind).toBe("matches");
    }
  });

  it("reports truncated runs as partial coverage with a reason", () => {
    const report = parse(asciiImage("A".repeat(128)), {
      max_string_bytes: 64,
    });
    expect(report.coverage.status).toBe("partial");
    expect(report.coverage.truncated_strings).toBeGreaterThan(0);
    expect(report.coverage.reason).toContain("exceeded max_string_bytes");
    expect(report.limitations).toEqual(
      expect.arrayContaining([
        expect.stringContaining("bytes beyond each retained prefix"),
      ]),
    );
  });

  it("rejects a malformed container instead of scanning arbitrary bytes", () => {
    const bytes = Buffer.from("not a native image", "latin1");
    expect(() =>
      parseNativeRiskSignatures(bytes, artifact(bytes), input()),
    ).toThrow(BinaryFormatFailure);
  });
});
