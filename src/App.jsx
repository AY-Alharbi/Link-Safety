
import { useState } from "react";
import { analyzeUrl } from "./utils/analysis/analyze.js";

const EXAMPLES = [
  {
    label: "Standard URL",
    url: "https://www.wikipedia.org/",
  },
  {
    label: "IP address",
    url: "http://192.168.1.10/login",
  },
  {
    label: "URL credentials",
    url: "https://paypal.com@untrusted.example/login",
  },
];

const RISK_LABELS = {
  low: "Low observed risk",
  moderate: "Moderate observed risk",
  high: "High observed risk",
  inconclusive: "Limited visibility",
};

const SEVERITY_LABELS = {
  info: "Informational",
  low: "Low",
  medium: "Medium",
  high: "High",
};

// --------------------------------------------------
// Risk Assessment
// --------------------------------------------------

function RiskAssessment({ risk }) {
  if (!risk) return null;

  const level = risk.level || "inconclusive";

  const score = Number.isFinite(risk.heuristicScore)
    ? Math.min(100, Math.max(0, risk.heuristicScore))
    : 0;

  return (
    <section className={`assessment-panel panel-${level}`}>
      <div className="assessment-heading">
        <div>
          <span className="eyebrow">RISK ASSESSMENT</span>
          <h2>{RISK_LABELS[level] || level}</h2>
        </div>

        <div className="score-display">
          <strong>{score}</strong>
          <span>/ 100</span>
        </div>
      </div>

      <div
        className="score-track"
        role="progressbar"
        aria-label="Heuristic indicator index"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
      >
        <span style={{ width: `${score}%` }} />
      </div>

      {risk.reasoning?.length > 0 && (
        <div className="assessment-reasoning">
          {risk.reasoning.map((item, index) => (
            <p key={index}>{item}</p>
          ))}
        </div>
      )}

      <p className="score-disclaimer">
        The heuristic score summarizes configured indicators.
        It is not a probability of malicious activity.
      </p>
    </section>
  );
}

// --------------------------------------------------
// URL Observations
// --------------------------------------------------

function Observations({ parsed, features }) {
  const items = [
    ["Protocol", parsed.scheme?.toUpperCase()],
    ["Hostname", parsed.hostname],
    ["Registered domain (approx.)", parsed.registrableDomain],
    ["Subdomains", features.subdomain_count],
    ["Hostname length", features.hostname_length],
    ["Path", parsed.path || "/"],
    ["Path depth", features.path_depth],
    ["Query parameters", features.query_param_count],
    ["Query length", features.query_length],
    ["HTTPS", parsed.usesHttps ? "Yes" : "No"],
    ["IP address hostname", parsed.hasIPAddress ? "Yes" : "No"],
    ["Embedded credentials", parsed.hasCredentials ? "Yes" : "No"],
    ["Punycode", parsed.containsPunycode ? "Yes" : "No"],
    ["Non-standard port", parsed.usesNonStandardPort ? "Yes" : "No"],
  ];

  return (
    <section className="report-section">
      <div className="section-heading">
        <div>
          <span className="eyebrow">URL STRUCTURE</span>
          <h2>Technical observations</h2>
        </div>
      </div>

      <div className="observations-grid">
        {items.map(([label, value]) => (
          <div className="observation" key={label}>
            <span>{label}</span>
            <strong>
              {value === undefined || value === null || value === ""
                ? "Not available"
                : String(value)}
            </strong>
          </div>
        ))}
      </div>
    </section>
  );
}

// --------------------------------------------------
// Finding
// --------------------------------------------------

function FindingCard({ finding }) {
  const severity = finding.severity || "info";

  return (
    <article className={`finding-card sev-${severity}`}>
      <div className="finding-heading">
        <div>
          <h3>{finding.title}</h3>
          <span className="finding-id">{finding.id}</span>
        </div>

        <span className={`severity severity-${severity}`}>
          {SEVERITY_LABELS[severity] || severity}
        </span>
      </div>

      {finding.description && (
        <p className="finding-description">
          {finding.description}
        </p>
      )}

      {finding.evidence && (
        <div className="finding-evidence">
          <span>OBSERVED EVIDENCE</span>
          <p>{finding.evidence}</p>
        </div>
      )}

      {finding.rationale && (
        <div className="finding-detail">
          <strong>Why it matters</strong>
          <p>{finding.rationale}</p>
        </div>
      )}

      {finding.benignExplanations && (
        <div className="finding-detail">
          <strong>Possible benign explanation</strong>
          <p>{finding.benignExplanations}</p>
        </div>
      )}
    </article>
  );
}

// --------------------------------------------------
// Findings Section
// --------------------------------------------------

function Findings({ findings }) {
  return (
    <section className="report-section">
      <div className="section-heading">
        <div>
          <span className="eyebrow">DETECTION RESULTS</span>
          <h2>Indicators & findings</h2>
        </div>

        <span className="count-label">
          {findings.length} {findings.length === 1 ? "finding" : "findings"}
        </span>
      </div>

      {findings.length > 0 ? (
        <div className="findings-list">
          {findings.map((finding, index) => (
            <FindingCard
              key={finding.id || index}
              finding={finding}
            />
          ))}
        </div>
      ) : (
        <div className="no-findings">
          <strong>No configured indicators were triggered.</strong>
          <p>
            This does not establish that the destination is safe.
          </p>
        </div>
      )}
    </section>
  );
}

// --------------------------------------------------
// Secondary Information
// --------------------------------------------------

function AdditionalDetails({ report }) {
  const recommendations = report.risk?.recommendations || [];
  const uncertainty = report.uncertainty || [];
  const limitations = report.limitations || [];

  return (
    <section className="additional-details">
      {recommendations.length > 0 && (
        <details>
          <summary>Recommendations</summary>

          <ul>
            {recommendations.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </details>
      )}

      {uncertainty.length > 0 && (
        <details>
          <summary>What remains unknown</summary>

          <ul>
            {uncertainty.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </details>
      )}

      <details>
        <summary>Methodology & limitations</summary>

        <div className="methodology-content">
          <div className="methodology-item">
            <span>Analysis method</span>
            <p>Rule-based static URL analysis.</p>
            <p>
              URL features are evaluated against configured detection
              rules to produce an explainable heuristic assessment.
            </p>
          </div>

          <div className="methodology-item">
            <span>Machine learning</span>
            <p>Not currently integrated.</p>
          </div>

          {limitations.length > 0 && (
            <div className="methodology-item">
              <span>Limitations</span>

              <ul>
                {limitations.map((item, index) => (
                  <li key={index}>{item}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </details>
    </section>
  );
}

// --------------------------------------------------
// Analysis Report
// --------------------------------------------------

function AnalysisReport({ report }) {
  const parsed = report.parsed || {};
  const features = report.features || {};
  const findings = report.findings || [];
  const risk = report.risk || {};

  return (
    <section className="report" aria-live="polite">
      <div className="report-heading">
        <div>
          <span className="eyebrow">ANALYSIS REPORT</span>
          <h2>Results</h2>
        </div>

        <span className="case-id">
          {(report.analysisId || "CASE").slice(0, 13).toUpperCase()}
        </span>
      </div>

      <RiskAssessment risk={risk} />

      <Findings findings={findings} />

      <Observations
        parsed={parsed}
        features={features}
      />

      <AdditionalDetails report={report} />
    </section>
  );
}

// --------------------------------------------------
// Main Application
// --------------------------------------------------

export default function App() {
  const [url, setUrl] = useState("");
  const [report, setReport] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function handleAnalyze(event) {
    event.preventDefault();

    setError("");
    setReport(null);

    if (!url.trim()) {
      setError("Enter a URL before starting the analysis.");
      return;
    }

    setLoading(true);

    try {
      const result = analyzeUrl(url);


      if (!result || result.ok !== true || !result.report) {
        setError(
          result?.message || "The URL could not be analyzed."
        );
        return;
      }

      setReport(result.report);
    } catch (err) {
      console.error("URL analysis failed:", err);

      setError(
        err instanceof Error
          ? err.message
          : "An unexpected error occurred."
      );
    } finally {
      setLoading(false);
    }
  }

  function handleExample(exampleUrl) {
    setUrl(exampleUrl);
    setError("");
    setReport(null);
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <a href="#" className="brand" aria-label="Link Safety home">
          <span className="brand-mark">L</span>
          <span>LINK SAFETY</span>
        </a>

        <span className="topbar-note">
          STATIC URL ANALYSIS
        </span>
      </header>

      <section className="hero">
        <span className="eyebrow">URL SECURITY ANALYSIS</span>

        <h1>
          Read the link before you <span>trust it.</span>
        </h1>

        <p>
          Examine URL structure and understand the evidence
          behind each security assessment.
        </p>
      </section>

      <section className="workspace">
        <div className="workspace-heading">
          <h2>Inspect a URL</h2>

          <span className="privacy-label">
            <span className="privacy-dot" />
            Local analysis
          </span>
        </div>

        <form onSubmit={handleAnalyze}>
          <label htmlFor="url-input">URL address</label>

          <div className="input-row">
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(event) => {
                setUrl(event.target.value);
                setError("");
              }}
              placeholder="https://example.com"
              maxLength={2048}
              autoComplete="off"
              spellCheck="false"
              aria-invalid={Boolean(error)}
              aria-describedby={error ? "url-error" : undefined}
            />

            <button
              type="submit"
              disabled={loading}
              aria-busy={loading}
              className="analyze-button"
            >
              {loading ? "Analyzing..." : "Analyze URL"}
            </button>
          </div>

          {error && (
            <p className="error-message" id="url-error" role="alert">
              {error}
            </p>
          )}
        </form>

        <div className="examples">
          <span>EXAMPLES</span>

          <div className="example-list">
            {EXAMPLES.map((example) => (
              <button
                type="button"
                key={example.label}
                title={example.url}
                onClick={() => handleExample(example.url)}
              >
                {example.label}
              </button>
            ))}
          </div>
        </div>
      </section>

      {report ? (
        <AnalysisReport report={report} />
      ) : (
        <p className="empty-state">
          Enter a URL to begin static analysis.
        </p>
      )}

      <footer className="footer">
        <span>LINK SAFETY</span>
        <span>Evidence, not verdicts.</span>
      </footer>
    </main>
  );
}
