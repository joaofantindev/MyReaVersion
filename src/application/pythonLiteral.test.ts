import { expect, it } from "vitest";

import { pythonLiteral } from "./pythonLiteral.js";

it("serializes JSON names as Python literals", () => {
  expect(pythonLiteral(null)).toBe("None");
  expect(pythonLiteral(true)).toBe("True");
  expect(pythonLiteral(false)).toBe("False");
  expect(pythonLiteral(12)).toBe("12");
});

it("keeps string contents data even when they resemble JSON names", () => {
  expect(pythonLiteral("null true false")).toBe('"null true false"');
  expect(pythonLiteral('x"); raise SystemExit("injected"); #')).toBe(
    '"x\\"); raise SystemExit(\\"injected\\"); #"',
  );
});

it("renders nested arrays and objects as formatted Python", () => {
  expect(pythonLiteral({ kind: "address", value: "0x401136" })).toBe(
    '{\n  "kind": "address",\n  "value": "0x401136"\n}',
  );
  expect(pythonLiteral([null, "null", { enabled: true }])).toBe(
    '[\n  None,\n  "null",\n  {\n    "enabled": True\n  }\n]',
  );
});
