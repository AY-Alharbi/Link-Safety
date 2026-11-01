
import { parseUrl } from "./parser.js";
import { extractFeatures } from "./features.js";
import { runRules } from "./rules.js";
import { assessRisk } from "./risk.js";

export const METHODOLOGY_VERSION = "lsi-rules-1.2.0";

export const LIMITATIONS = [
  "Analysis is lexical and static. The submitted URL is never opened, visited, resolved through DNS, or requested.",
  "The registrable domain is estimated using a limited static suffix list, not the complete Public Suffix List.",
  "Brand and keyword indicators depend on static rule lists and may miss new impersonation techniques.",
  "A compromised legitimate website may not show suspicious URL characteristics.",
  "The heuristic score summarizes observed rule evidence. It is not a probability of maliciousness.",
  "URL text analysis cannot inspect page content, redirects, certificates, or server behavior.",
];

function createAnalysisId() {
  return (
    globalThis.crypto?.randomUUID?.() ||
    `case-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  );
}

function sanitizeInput(input, hasCredentials) {
  if (!hasCredentials) return input;

  return input.replace(
    /\/\/[^/?#]*@/,
    "//***@"
  );
}

/**
 * Pure synchronous analysis pipeline.
 * No network requests are made.
 */
export function analyzeUrl(raw, id = createAnalysisId()) {
  const parsed = parseUrl(raw);

  if (!parsed.success) {
    return {
      ok: false,
      error: "VALIDATION_ERROR",
      message: parsed.error,
    };
  }

  const p = parsed.data;

  const features = extractFeatures(p);

  const findings = runRules(p, features);

  const risk = assessRisk(findings);

  const uncertainty = [];

  if (findings.length === 0) {
    uncertainty.push(
      "No suspicious indicators were detected. This does not prove that the URL is safe."
    );
  }

  if (p.hostType === "localhost" || p.labels.length === 1) {
    uncertainty.push(
      "This hostname is local or single-label. Some domain-based rules may have limited applicability."
    );
  }

  if (p.hasNonAsciiHost || p.punycodeLabels.length > 0) {
    uncertainty.push(
      "Internationalized hostname detected. Visual similarity and homograph risks cannot be fully assessed by this analysis."
    );
  }

  if (features.is_known_shortener) {
    uncertainty.push(
      "The visible URL belongs to a known URL-shortening service. Its final destination has not been inspected."
    );
  }

  const safeInput = sanitizeInput(p.input, p.hasCredentials);

  const safeParsed = {
    ...p,
    input: safeInput,
    username: null,
    password: null,
  };

  return {
    ok: true,

    report: {
      analysisId: id,
      analyzedAt: new Date().toISOString(),
      methodologyVersion: METHODOLOGY_VERSION,

      validation: {
        valid: true,
      },

      parsed: safeParsed,
      features,
      findings,
      risk,
      uncertainty,
      limitations: LIMITATIONS,

      ml: {
        status: "unavailable",
        message: "No trained machine-learning model is connected.",
      },
    },
  };
}
