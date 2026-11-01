import {
  SHORTENERS,
  findSuspiciousKeywords,
  shannonEntropy,
} from "./rules.js";

// Static feature descriptions for the methodology/report UI.
export const FEATURE_DOCS = {
  url_length: "Characters in the submitted URL.",
  hostname_length: "Characters in the normalized hostname.",
  subdomain_count: "Labels before the registrable domain.",
  dot_count: "Number of dots in the full URL.",
  hyphen_count: "Number of hyphens in the full URL.",
  host_hyphen_count: "Number of hyphens in the hostname.",
  digit_count: "Number of digits in the full URL.",
  host_digit_count: "Number of digits in the hostname.",
  special_char_count: "Characters outside the common URL character set.",
  query_param_count: "Number of query parameters.",
  path_length: "Number of characters in the URL path.",
  query_length: "Number of characters in the query string.",
  path_depth: "Number of non-empty path segments.",
  is_ip_host: "Hostname is an IPv4 or IPv6 address.",
  has_at_symbol: "The URL contains an @ symbol.",
  has_userinfo: "The URL contains username or password information.",
  is_https: "The URL uses HTTPS. This does not establish trustworthiness.",
  has_nonstandard_port: "An explicit non-default port is present.",
  percent_encoded_count: "Number of percent-encoded sequences.",
  percent_encoding_ratio: "Share of URL characters represented by percent encoding.",
  punycode_label_count: "Number of hostname labels beginning with xn--.",
  has_non_ascii_host: "The submitted hostname contains non-ASCII characters.",
  is_known_shortener: "The registrable domain matches a static shortener list.",
  suspicious_keywords:
    "Credential or urgency-related keywords found in the hostname, path, or query.",
  hostname_suspicious_keywords:
    "Sensitive-action keywords found in the hostname.",
  path_suspicious_keywords:
    "Sensitive-action keywords found in the URL path.",
  query_suspicious_keywords:
    "Sensitive-action keywords found in the query string.",
  embedded_url_in_query_or_path:
    "Another HTTP(S) URL appears in the path or query.",
  double_slash_in_path:
    "A repeated slash appears inside the path.",
  hostname_entropy:
    "Shannon entropy of the hostname without dots.",
  longest_host_label:
    "Length of the longest hostname label.",
};

function countMatches(value, pattern) {
  return (String(value).match(pattern) || []).length;
}

function safeDecode(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    // Keep the original text if it contains malformed percent encoding.
    return value;
  }
}

function getUniqueKeywords(...groups) {
  return [...new Set(groups.flat())];
}

export function extractFeatures(parsed) {
  const input = parsed.input || "";
  const hostname = parsed.hostname || "";
  const path = parsed.path || "/";
  const query = parsed.query || "";

  const labels = parsed.labels || hostname.split(".").filter(Boolean);

  const registrableLabels = parsed.registrableDomain
    ? parsed.registrableDomain.split(".").length
    : 0;

  // Decode path and query separately to identify
  // where suspicious keywords appear.
  const decodedPath = safeDecode(path).toLowerCase();
  const decodedQuery = safeDecode(query).toLowerCase();

  const searchableHostname = hostname.toLowerCase();

  const hostnameKeywords =
    findSuspiciousKeywords(searchableHostname);

  const pathKeywords =
    findSuspiciousKeywords(decodedPath);

  const queryKeywords =
    findSuspiciousKeywords(decodedQuery);

  const allSuspiciousKeywords = getUniqueKeywords(
    hostnameKeywords,
    pathKeywords,
    queryKeywords
  );

  const decodedPathAndQuery = `${decodedPath}?${decodedQuery}`;

  const percentEncodedCount =
    parsed.percentEncodedCount ??
    countMatches(input, /%[0-9a-f]{2}/gi);

  const isKnownShortener =
    Boolean(parsed.registrableDomain) &&
    SHORTENERS.has(parsed.registrableDomain.toLowerCase());

  return {
    url_length: input.length,

    hostname_length: hostname.length,

    subdomain_count:
      parsed.hostType === "domain"
        ? Math.max(0, labels.length - registrableLabels)
        : 0,

    dot_count: countMatches(input, /\./g),

    hyphen_count: countMatches(input, /-/g),

    host_hyphen_count: countMatches(hostname, /-/g),

    digit_count: countMatches(input, /\d/g),

    host_digit_count: countMatches(hostname, /\d/g),

    special_char_count: countMatches(
      input,
      /[^A-Za-z0-9./:-]/g
    ),

    query_param_count: (parsed.queryParams || []).length,

    path_length: path.length,

    query_length: query.length,

    path_depth: path.split("/").filter(Boolean).length,

    is_ip_host: parsed.hostType === "ip",

    has_at_symbol: input.includes("@"),

    has_userinfo:
      Boolean(parsed.hasUsername) ||
      Boolean(parsed.hasPassword),

    is_https: parsed.scheme === "https",

    has_nonstandard_port: Boolean(parsed.usesNonStandardPort),

    percent_encoded_count: percentEncodedCount,

    percent_encoding_ratio:
      input.length > 0
        ? Math.round(
            ((percentEncodedCount * 3) / input.length) * 1000
          ) / 1000
        : 0,

    punycode_label_count: (parsed.punycodeLabels || []).length,

    has_non_ascii_host: Boolean(parsed.hasNonAsciiHost),

    is_known_shortener: isKnownShortener,

    // Combined field used by the existing detection rule.
    suspicious_keywords: allSuspiciousKeywords,

    // Detailed fields identify where keywords were found.
    hostname_suspicious_keywords: hostnameKeywords,

    path_suspicious_keywords: pathKeywords,

    query_suspicious_keywords: queryKeywords,

    embedded_url_in_query_or_path:
      /https?:\/\//i.test(decodedPathAndQuery),

    double_slash_in_path: path.includes("//"),

    hostname_entropy: shannonEntropy(
      hostname.replace(/\./g, "")
    ),

    longest_host_label: labels.reduce(
      (maximum, label) => Math.max(maximum, label.length),
      0
    ),
  };
}