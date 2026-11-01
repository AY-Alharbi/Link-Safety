
import { describe, it, expect } from "vitest";

import { parseUrl } from "../src/utils/analysis/parser.js";
import { extractFeatures } from "../src/utils/analysis/features.js";
import { runRules } from "../src/utils/analysis/rules.js";
import { assessRisk } from "../src/utils/analysis/risk.js";
import { analyzeUrl } from "../src/utils/analysis/analyze.js";

describe("URL Parser", () => {
  it("accepts a valid HTTPS URL", () => {
    const result = parseUrl("https://example.com");

    expect(result.success).toBe(true);
  });

  it("rejects unsupported protocols", () => {
    const result = parseUrl("ftp://example.com");

    expect(result.success).toBe(false);
  });

  it("rejects an empty URL", () => {
    const result = parseUrl("");

    expect(result.success).toBe(false);
  });

  it("rejects URLs containing backslashes", () => {
    const result = parseUrl("https://example.com\\@evil.com");

    expect(result.success).toBe(false);
  });
});

describe("Feature Extraction", () => {
  it("extracts HTTPS information", () => {
    const parsed = parseUrl("https://example.com").data;
    const features = extractFeatures(parsed);

    expect(features.is_https).toBe(true);
  });

  it("detects IP-based hosts", () => {
    const parsed = parseUrl("http://192.168.1.1").data;
    const features = extractFeatures(parsed);

    expect(features.is_ip_host).toBe(true);
  });
});

describe("Rule Engine", () => {
  it("detects sensitive-action keywords", () => {
    const parsed = parseUrl("https://example.com/login").data;
    const features = extractFeatures(parsed);
    const findings = runRules(parsed, features);

    expect(
      findings.some((item) => item.id === "LSI-R004")
    ).toBe(true);
  });

  it("detects a known URL shortener", () => {
    const parsed = parseUrl("https://bit.ly/example").data;
    const features = extractFeatures(parsed);
    const findings = runRules(parsed, features);

    expect(
      findings.some((item) => item.id === "LSI-R011")
    ).toBe(true);
  });

  it("does not flag a normal URL without matching indicators", () => {
    const parsed = parseUrl("https://example.com").data;
    const features = extractFeatures(parsed);
    const findings = runRules(parsed, features);

    expect(findings).toHaveLength(0);
  });
});

describe("Risk Assessment", () => {
  it("returns low risk when there are no findings", () => {
    const result = assessRisk([]);

    expect(result.level).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("does not double-count findings in the same group", () => {
    const findings = [
      {
        id: "TEST-1",
        severity: "medium",
        group: "url-structure",
      },
      {
        id: "TEST-2",
        severity: "high",
        group: "url-structure",
      },
    ];

    const result = assessRisk(findings);

    expect(result.totalPoints).toBe(3);
    expect(result.groupContributions).toHaveLength(1);
  });

  it("returns limited visibility for a shortener-only finding", () => {
    const result = assessRisk([
      {
        id: "LSI-R011",
        severity: "info",
        group: "destination-visibility",
      },
    ]);

    expect(result.level).toBe("inconclusive");
  });
});

describe("Complete Analysis Pipeline", () => {
  it("returns a report for a valid URL", () => {
    const result = analyzeUrl("https://example.com");

    expect(result.ok).toBe(true);
    expect(result.report).toBeDefined();
    expect(result.report.risk.level).toBe("low");
  });

  it("returns a validation error for an invalid URL", () => {
    const result = analyzeUrl("not-a-valid-url");

    expect(result.ok).toBe(false);
    expect(result.error).toBe("VALIDATION_ERROR");
  });

  it("does not claim that a machine-learning model is connected", () => {
    const result = analyzeUrl("https://example.com");

    expect(result.report.ml.status).toBe("unavailable");
  });
});
