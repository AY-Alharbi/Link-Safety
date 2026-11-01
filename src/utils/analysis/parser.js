const MAX_URL_LENGTH = 2048;

const MULTI_PART_SUFFIXES = [
  "co.uk",
  "org.uk",
  "ac.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "com.sa",
  "com.eg",
  "co.jp",
  "co.in",
];

function isValidIPv4(hostname) {
  const parts = hostname.split(".");

  if (parts.length !== 4) return false;

  return parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;

    const number = Number(part);
    return number >= 0 && number <= 255;
  });
}

function isIPv6(hostname) {
  return hostname.includes(":");
}

function isIPAddress(hostname) {
  return isValidIPv4(hostname) || isIPv6(hostname);
}

function getDomainParts(hostname) {
  const cleanHost = hostname.toLowerCase().replace(/\.$/, "");

  if (isIPAddress(cleanHost) || cleanHost === "localhost") {
    return {
      hostname: cleanHost,
      labels: [cleanHost],
      subdomain: "",
      registrableDomain: cleanHost,
      tld: "",
    };
  }

  const labels = cleanHost.split(".");
  const tld = labels[labels.length - 1] || "";

  let suffixLength = 1;

  if (labels.length >= 3) {
    const lastTwo = labels.slice(-2).join(".");

    if (MULTI_PART_SUFFIXES.includes(lastTwo)) {
      suffixLength = 2;
    }
  }

  const registrableIndex = labels.length - suffixLength - 1;

  if (registrableIndex < 0) {
    return {
      hostname: cleanHost,
      labels,
      subdomain: "",
      registrableDomain: cleanHost,
      tld,
    };
  }

  return {
    hostname: cleanHost,
    labels,
    registrableDomain: labels.slice(registrableIndex).join("."),
    subdomain: labels.slice(0, registrableIndex).join("."),
    tld,
  };
}

function createError(message) {
  return {
    success: false,
    error: message,
    data: null,
  };
}

function countPercentEncoding(value) {
  return (value.match(/%[0-9a-f]{2}/gi) || []).length;
}

function getRawHostname(input) {
  const match = input.match(/^https?:\/\/([^/?#]*)/i);

  if (!match) return "";

  let authority = match[1];

  // Remove username and password if present.
  authority = authority.substring(authority.lastIndexOf("@") + 1);

  // IPv6 hostnames are enclosed in brackets.
  if (authority.startsWith("[")) {
    const closingBracket = authority.indexOf("]");

    if (closingBracket === -1) return "";

    return authority.slice(1, closingBracket);
  }

  // Remove the port.
  return authority.replace(/:\d+$/, "");
}

export function parseUrl(rawInput) {
  if (typeof rawInput !== "string") {
    return createError("URL must be a text value.");
  }

  const input = rawInput.trim();

  if (!input) {
    return createError("Please enter a URL.");
  }

  if (input.length > MAX_URL_LENGTH) {
    return createError("URL exceeds the maximum allowed length.");
  }

  if (/[\s\u0000-\u001F\u007F]/.test(input)) {
    return createError("URL contains whitespace or control characters.");
  }

  if (input.includes("\\")) {
    return createError("Backslashes are not accepted in URLs.");
  }

  if (!/^https?:\/\//i.test(input)) {
    return createError("Only HTTP and HTTPS URLs are supported.");
  }

  let parsed;

  try {
    parsed = new URL(input);
  } catch {
    return createError("The URL format is invalid.");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return createError("Unsupported URL protocol.");
  }

  if (!parsed.hostname) {
    return createError("URL hostname is missing.");
  }

  const hostname = parsed.hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");

  const isIP = isIPAddress(hostname);
  const isLocalhost = hostname === "localhost";

  const domainInfo = getDomainParts(hostname);

  const pathSegments = parsed.pathname
    .split("/")
    .filter(Boolean);

  const queryParams = Array.from(parsed.searchParams.entries());

  // The URL API normalizes explicitly supplied default ports.
  const usesNonStandardPort = parsed.port !== "";

  const rawHostname = getRawHostname(input);

  const hasNonAsciiHost = /[^\x00-\x7F]/.test(rawHostname);

  const punycodeLabels = hostname
    .split(".")
    .filter((label) => label.startsWith("xn--"));

  const percentEncodedCount = countPercentEncoding(input);

  const data = {
    // Original submitted URL
    input,

    // URL structure
    scheme: parsed.protocol.replace(":", ""),
    protocol: parsed.protocol.replace(":", ""),
    hostname: domainInfo.hostname,
    registrableDomain: domainInfo.registrableDomain,
    subdomain: domainInfo.subdomain,
    tld: domainInfo.tld,
    labels: domainInfo.labels,

    // Host classification
    hostType: isIP ? "ip" : isLocalhost ? "localhost" : "domain",
    isIPAddress: isIP,

    // Port and authentication
    port: parsed.port || null,
    hasUsername: parsed.username.length > 0,
    hasPassword: parsed.password.length > 0,
    hasCredentials:
      parsed.username.length > 0 || parsed.password.length > 0,

    // Path and query
    path: parsed.pathname,
    query: parsed.search.slice(1),
    fragment: parsed.hash.slice(1),
    queryParams,
    pathSegments,
    pathDepth: pathSegments.length,
    queryParameterCount: queryParams.length,
    hasQuery: parsed.search.length > 0,
    hasFragment: parsed.hash.length > 0,

    // Protocol
    usesHttps: parsed.protocol === "https:",
    isHttps: parsed.protocol === "https:",
    usesNonStandardPort,

    // IP information
    hasIPAddress: isIP,
    ipVersion: isIP ? (isIPv6(hostname) ? 6 : 4) : null,

    // Encoding and hostname properties
    containsNonAscii: /[^\x00-\x7F]/.test(input),
    hasNonAsciiHost,
    containsPunycode: punycodeLabels.length > 0,
    punycodeLabels,
    percentEncodedCount,

    // Length
    hostnameLength: hostname.length,
  };

  return {
    success: true,
    error: null,
    data,
  };
}