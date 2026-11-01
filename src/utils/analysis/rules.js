
export const SHORTENERS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
  "cutt.ly",
  "shorturl.at",
  "rb.gy",
  "tiny.cc",
  "bl.ink",
  "t.ly",
  "s.id",
  "v.gd",
  "lnkd.in",
]);

export const SUSPICIOUS_KEYWORDS = [
  "login",
  "signin",
  "sign-in",
  "logon",
  "verify",
  "verification",
  "account",
  "update",
  "secure",
  "security",
  "banking",
  "confirm",
  "password",
  "passwd",
  "credential",
  "wallet",
  "webscr",
  "suspend",
  "unlock",
  "billing",
  "invoice",
  "recover",
  "authenticate",
];

const TOKEN_KEYWORDS = SUSPICIOUS_KEYWORDS.filter(
  (keyword) => !keyword.includes("-")
);

const HYPHEN_KEYWORDS = SUSPICIOUS_KEYWORDS.filter(
  (keyword) => keyword.includes("-")
);

function tokenize(value) {
  return new Set(
    value
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean)
  );
}

export function findSuspiciousKeywords(searchable) {
  const value = String(searchable || "");
  const tokens = tokenize(value);
  const lower = value.toLowerCase();

  return [
    ...TOKEN_KEYWORDS.filter((keyword) => tokens.has(keyword)),
    ...HYPHEN_KEYWORDS.filter((keyword) => lower.includes(keyword)),
  ];
}

export function shannonEntropy(value) {
  if (!value) return 0;

  const frequencies = new Map();

  for (const character of value) {
    frequencies.set(
      character,
      (frequencies.get(character) || 0) + 1
    );
  }

  let entropy = 0;

  for (const frequency of frequencies.values()) {
    const probability = frequency / value.length;
    entropy -= probability * Math.log2(probability);
  }

  return Math.round(entropy * 1000) / 1000;
}

function finding({
  id,
  title,
  description,
  severity,
  group,
  evidence,
}) {
  return {
    id,
    title,
    description,
    severity,
    group,
    evidence,
  };
}

/**
 * Rule-based URL inspection.
 * Findings describe observable indicators, not proof of maliciousness.
 */
export function runRules(parsed, features) {
  const findings = [];

  // R001: URL contains embedded username or password.
  if (features.has_userinfo) {
    findings.push(
      finding({
        id: "LSI-R001",
        title: "URL contains user information",
        description:
          "The URL contains a username or password before the hostname. This can be used to make a misleading link appear legitimate.",
        severity: "high",
        group: "url-structure",
        evidence: "Username or password component detected.",
      })
    );
  }

  // R002: A literal IP address is used as the host.
  if (features.is_ip_host) {
    findings.push(
      finding({
        id: "LSI-R002",
        title: "IP address used as hostname",
        description:
          "The destination is represented by a literal IP address instead of a conventional domain name.",
        severity: "medium",
        group: "host-identity",
        evidence: `Hostname: ${parsed.hostname}`,
      })
    );
  }

  // R003: Known URL shortener.
  if (features.is_known_shortener) {
    findings.push(
      finding({
        id: "LSI-R011",
        title: "Known URL shortener",
        description:
          "The visible hostname belongs to a known URL-shortening service. The final destination is not visible in the submitted URL.",
        severity: "info",
        group: "destination-visibility",
        evidence: `Domain: ${parsed.registrableDomain}`,
      })
    );
  }

  // R004: Suspicious credential or urgency-related words.
  if (features.suspicious_keywords.length > 0) {
    findings.push(
      finding({
        id: "LSI-R004",
        title: "Sensitive-action keywords detected",
        description:
          "The URL contains words commonly associated with authentication, account recovery, verification, or financial actions. These words can also appear in legitimate URLs.",
        severity: "low",
        group: "url-language",
        evidence: features.suspicious_keywords.join(", "),
      })
    );
  }

  // R005: Punycode hostname labels.
  if (features.punycode_label_count > 0) {
    findings.push(
      finding({
        id: "LSI-R005",
        title: "Internationalized hostname encoding",
        description:
          "One or more hostname labels use Punycode encoding. This is not inherently malicious, but internationalized domains can be relevant to look-alike domain investigations.",
        severity: "medium",
        group: "hostname-identity",
        evidence: `${features.punycode_label_count} Punycode label(s) detected.`,
      })
    );
  }

  // R006: Embedded URL inside path or query.
  if (features.embedded_url_in_query_or_path) {
    findings.push(
      finding({
        id: "LSI-R006",
        title: "Embedded URL detected",
        description:
          "Another HTTP or HTTPS URL appears inside the submitted URL's path or query. This can occur in redirect parameters and nested links.",
        severity: "medium",
        group: "url-structure",
        evidence: "Nested HTTP(S) URL pattern detected.",
      })
    );
  }

  // R007: Non-standard port.
  if (features.has_nonstandard_port) {
    findings.push(
      finding({
        id: "LSI-R007",
        title: "Non-standard port",
        description:
          "The URL specifies a port other than the default port for its scheme. This may be legitimate but deserves context.",
        severity: "low",
        group: "network-addressing",
        evidence: `Port: ${parsed.port}`,
      })
    );
  }

  // R008: Unusually long URL.
  if (features.url_length > 250) {
    findings.push(
      finding({
        id: "LSI-R008",
        title: "Unusually long URL",
        description:
          "The submitted URL is unusually long. Long URLs may contain tracking data, nested parameters, or obfuscated content.",
        severity: "medium",
        group: "url-complexity",
        evidence: `${features.url_length} characters.`,
      })
    );
  } else if (features.url_length > 120) {
    findings.push(
      finding({
        id: "LSI-R008",
        title: "Long URL",
        description:
          "The submitted URL is longer than a typical short link. Length alone does not establish malicious intent.",
        severity: "low",
        group: "url-complexity",
        evidence: `${features.url_length} characters.`,
      })
    );
  }

  // R009: Multiple subdomains.
  if (features.subdomain_count >= 4) {
    findings.push(
      finding({
        id: "LSI-R009",
        title: "Deep subdomain structure",
        description:
          "The hostname contains several subdomain labels. This can make the actual registrable domain harder to notice.",
        severity: "medium",
        group: "host-structure",
        evidence: `${features.subdomain_count} subdomain label(s).`,
      })
    );
  } else if (features.subdomain_count >= 2) {
    findings.push(
      finding({
        id: "LSI-R009",
        title: "Multiple subdomains",
        description:
          "The hostname contains multiple subdomain labels. This is common in legitimate services but should be interpreted in context.",
        severity: "low",
        group: "host-structure",
        evidence: `${features.subdomain_count} subdomain label(s).`,
      })
    );
  }

  // R010: High percent-encoding ratio.
  if (
    features.percent_encoded_count >= 5 &&
    features.percent_encoding_ratio >= 0.1
  ) {
    findings.push(
      finding({
        id: "LSI-R010",
        title: "Heavy percent encoding",
        description:
          "A notable portion of the URL uses percent encoding. Encoding is normal in URLs, but unusually heavy use may obscure readable content.",
        severity: "medium",
        group: "url-obfuscation",
        evidence: `${features.percent_encoded_count} encoded sequence(s); ratio ${features.percent_encoding_ratio}.`,
      })
    );
  }

  // R012: Repeated slash inside the path.
  if (features.double_slash_in_path) {
    findings.push(
      finding({
        id: "LSI-R012",
        title: "Repeated slash in path",
        description:
          "The URL path contains consecutive slashes. This may be harmless but can be relevant when inspecting unusual URL structures.",
        severity: "low",
        group: "url-structure",
        evidence: "Consecutive slashes detected in path.",
      })
    );
  }

  // R013: Unusually high hostname entropy.
  if (
    features.hostname_length >= 15 &&
    features.hostname_entropy >= 3.8
  ) {
    findings.push(
      finding({
        id: "LSI-R013",
        title: "High hostname character diversity",
        description:
          "The hostname has relatively high character diversity. Random-looking hostnames can occur in generated infrastructure and are not proof of malicious activity.",
        severity: "low",
        group: "hostname-pattern",
        evidence: `Entropy: ${features.hostname_entropy} bits per character.`,
      })
    );
  }

  return findings;
}
