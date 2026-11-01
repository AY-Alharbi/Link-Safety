
export const SEVERITY_POINTS = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
};

export const SCORE_CAP = 9;
export const SHORTENER_RULE_ID = "LSI-R011";

/**
 * Aggregate findings by independent correlation groups.
 * The score is a heuristic evidence index, NOT a probability.
 */
export function assessRisk(findings = []) {
  const bestByGroup = new Map();

  for (const finding of findings) {
    const group = finding.group || "other";
    const severity = SEVERITY_POINTS[finding.severity];

    if (severity === undefined) continue;

    const current = bestByGroup.get(group);

    if (!current || severity > SEVERITY_POINTS[current.severity]) {
      bestByGroup.set(group, finding);
    }
  }

  const groupContributions = [...bestByGroup.entries()].map(
    ([group, finding]) => ({
      group,
      points: SEVERITY_POINTS[finding.severity],
      ruleId: finding.id,
    })
  );

  const totalPoints = groupContributions.reduce(
    (sum, item) => sum + item.points,
    0
  );

  const strongGroups = groupContributions.filter(
    (item) => item.points >= 2
  ).length;

  const hasHigh = groupContributions.some(
    (item) => item.points >= 3
  );

  const heuristicScore = Math.round(
    (Math.min(totalPoints, SCORE_CAP) / SCORE_CAP) * 100
  );

  const hasShortener = findings.some(
    (finding) => finding.id === SHORTENER_RULE_ID
  );

  const onlyShortener =
    hasShortener &&
    findings.every(
      (finding) =>
        finding.id === SHORTENER_RULE_ID ||
        finding.severity === "info" ||
        finding.severity === "low"
    );

  let level;
  const reasoning = [
    `${findings.length} finding(s) across ${groupContributions.length} independent group(s).`,
  ];

  if (totalPoints >= 6 && strongGroups >= 2) {
    level = "high";
    reasoning.push(
      "Multiple independent groups provide medium-or-higher evidence."
    );
  } else if (onlyShortener) {
    level = "inconclusive";
    reasoning.push(
      "The destination is hidden behind a URL shortener. The visible URL alone provides limited evidence."
    );
  } else if (totalPoints >= 3 || hasHigh) {
    level = "moderate";

    if (hasHigh && totalPoints < 6) {
      reasoning.push(
        "A strong indicator exists but lacks sufficient independent corroboration."
      );
    }
  } else {
    level = "low";
    reasoning.push(
      "The observed indicators did not reach the moderate threshold."
    );
  }

  const recommendations = {
    low: [
      "Low observed risk is not a safety guarantee.",
      "Confirm that the registrable domain is the one you expect before entering credentials.",
    ],

    moderate: [
      "Exercise caution and avoid entering credentials or payment details.",
      "Navigate to the organization using its known address.",
      "If the link arrived unexpectedly, verify it with the sender through another channel.",
    ],

    high: [
      "Do not open the link or submit personal information.",
      "Report the link to your security team or the impersonated organization.",
      "If credentials were entered, change them and enable multi-factor authentication.",
    ],

    inconclusive: [
      "Verify the destination using an approved, isolated URL expansion tool.",
      "Confirm the link with the sender through a separate communication channel.",
    ],
  };

  return {
    level,
    heuristicScore,
    totalPoints,
    groupContributions,
    reasoning,
    recommendations: recommendations[level],
  };
}
