/**
 * Serialize a JSON-like value as a Python literal.
 *
 * JSON and Python literals differ for null and booleans, so JSON.stringify
 * alone would emit `null`, `true`, or `false` as names. Strings still use JSON
 * escaping, which is valid Python string syntax for the values these planners
 * accept.
 */
export const pythonLiteral = (value: unknown, depth = 0): string => {
  if (value === null || value === undefined) return "None";
  if (value === true) return "True";
  if (value === false) return "False";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number")
    return Number.isFinite(value) ? String(value) : "None";
  const indent = "  ".repeat(depth);
  const childIndent = "  ".repeat(depth + 1);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    const items = value.map(
      (item) => `${childIndent}${pythonLiteral(item, depth + 1)}`,
    );
    return `[\n${items.join(",\n")}\n${indent}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value);
    if (entries.length === 0) return "{}";
    const items = entries.map(
      ([key, item]) =>
        `${childIndent}${JSON.stringify(key)}: ${pythonLiteral(item, depth + 1)}`,
    );
    return `{\n${items.join(",\n")}\n${indent}}`;
  }
  return "None";
};
