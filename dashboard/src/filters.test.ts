import { describe, expect, it } from "bun:test";
import {
  activeChips,
  clearAllFilters,
  clearFilter,
  isEmpty,
  parseFilters,
  resolveScope,
  serializeFilters,
  toggleFilter,
} from "./filters";

describe("filter URL state", () => {
  it("round-trips canonical parameters", () => {
    const filters = parseFilters(
      "?scope=report&reportId=42&severity=Critical&severity=High&status=NonCompliant&q=ssh",
    );
    expect(filters.scope).toEqual(["report"]);
    expect(filters.reportId).toEqual(["42"]);
    expect(filters.severity).toEqual(["Critical", "High"]);
    expect(filters.q).toEqual(["ssh"]);
    expect(parseFilters(serializeFilters(filters))).toEqual(filters);
  });

  it("sorts multi-values and dedupes for a stable shareable URL", () => {
    const filters = parseFilters("?severity=Low&severity=Critical&severity=Critical&category=ssh");
    expect(filters.severity).toEqual(["Critical", "Low"]);
    const once = serializeFilters(filters);
    const twice = serializeFilters(parseFilters(once));
    expect(twice).toBe(once);
    expect(once).toContain("severity=Critical&severity=Low");
  });

  it("ignores unknown keys and blank values", () => {
    const filters = parseFilters("?bogus=1&severity=&category=ssh&other=2") as Record<string, unknown>;
    expect(filters.bogus).toBeUndefined();
    expect(filters.other).toBeUndefined();
    expect(filters.severity).toBeUndefined();
    expect(filters.category).toEqual(["ssh"]);
  });

  it("keeps single-value keys to one value", () => {
    const filters = parseFilters("?scope=latest&scope=range&from=2026-01-01&from=2026-02-01");
    expect(filters.scope).toEqual(["latest"]);
    expect(filters.from).toEqual(["2026-01-01"]);
  });

  it("toggles multi-value filters on and off and clears them", () => {
    let filters = toggleFilter({}, "severity", "Critical");
    filters = toggleFilter(filters, "severity", "High");
    expect(filters.severity).toEqual(["Critical", "High"]);
    filters = toggleFilter(filters, "severity", "Critical");
    expect(filters.severity).toEqual(["High"]);
    expect(clearFilter(filters, "severity")).toEqual({});
  });

  it("toggles single-value filters like a radio", () => {
    let filters = toggleFilter({}, "scope", "report");
    expect(filters.scope).toEqual(["report"]);
    filters = toggleFilter(filters, "scope", "report");
    expect(filters.scope).toBeUndefined();
  });

  it("exposes chips in canonical order and a clear-all", () => {
    const filters = parseFilters("?severity=High&category=ssh&status=NonCompliant");
    expect(activeChips(filters)).toEqual([
      { key: "severity", value: "High" },
      { key: "category", value: "ssh" },
      { key: "status", value: "NonCompliant" },
    ]);
    expect(isEmpty(filters)).toBeFalse();
    expect(isEmpty(clearAllFilters())).toBeTrue();
  });

  it("resolves an unknown scope to latest", () => {
    expect(resolveScope(parseFilters("?scope=range"))).toBe("range");
    expect(resolveScope(parseFilters("?scope=whatever"))).toBe("latest");
    expect(resolveScope({})).toBe("latest");
  });
});
