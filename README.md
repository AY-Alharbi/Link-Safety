# Link Safety 

**Read the link before you trust it.**

Links are part of our everyday digital interactions, but not every link is as straightforward as it looks. A URL can contain unusual structures, misleading elements, or patterns that deserve a closer look.

I built Link Safety Intelligence to explore how much useful information can be extracted from a URL itself, before interacting with its destination.

The project analyzes URL text, looks for suspicious indicators, and presents its findings in a readable report. It does not open the submitted link or attempt to access the website.

## What it does

The tool examines different parts of a URL, including:

- **URL structure:** Checks for embedded credentials, unusual path structures, and other structural patterns.
- **Hostname:** Looks at IP-based hosts, subdomains, Punycode, and hostname characteristics.
- **URL patterns:** Identifies known URL shorteners, suspicious keywords, and encoded characters.
- **Risk assessment:** Combines the findings using a set of rules and assigns an indicative risk level.

The result is presented as an analysis report, showing the detected indicators and the reasoning behind the assessment.

## How the analysis works

The analysis follows a straightforward process:

1. **Parse:** Validate the submitted URL and extract its components.
2. **Extract features:** Collect structural and lexical characteristics from the URL.
3. **Apply rules:** Check the extracted features against predefined detection rules.
4. **Assess risk:** Combine the findings and calculate a heuristic score.
5. **Generate report:** Present the results, recommendations, and limitations.

Each stage has a specific responsibility, which makes the analysis easier to understand, test, and maintain.

## Technology

- React
- JavaScript
- Vite
- Vitest
- CSS

## Running the project locally

Make sure Node.js is installed, then run:

```bash
npm install
npm run dev
```

To run the tests:

```bash
npm test
```

To create a production build:

```bash
npm run build
```

## A note about the methodology

This project currently uses static URL analysis and predefined rules. It does not use a trained machine-learning model.

The submitted URL is never opened, visited, resolved through DNS, or requested. All analysis is performed on the URL text itself.

The risk score is a heuristic summary of the observed indicators, not a probability that a URL is malicious.

A low-risk result does not guarantee that a link is safe. Likewise, suspicious indicators do not independently prove malicious intent.

The tool also cannot inspect webpage content, redirects, certificates, or server behavior.

## Tests

The project includes automated tests covering the URL parser, feature extraction, rule engine, risk assessment, and complete analysis pipeline.

The current test suite contains 15 passing tests.

## Why I built it

I wanted to work on a cybersecurity project that goes beyond simply labeling a URL as safe or unsafe.

An important part of security analysis is understanding the evidence behind a finding, knowing what that evidence can tell us, and recognizing what remains unknown.

That is the approach I wanted to explore with this project.

---

*Link Safety Intelligence is a learning and portfolio project. Its results should not be used as the sole basis for security decisions.*
