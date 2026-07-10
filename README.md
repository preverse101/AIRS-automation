# Palo Alto Networks AIRS False Positive Analyzer

## Overview

The **AIRS False Positive Analyzer** is a Python utility designed to analyze **Palo Alto Networks Prisma AIRS (AI Runtime Security)** scan results and identify detections that are likely to be **false positives**.

Rather than manually reviewing every malicious detection, this tool retrieves detailed scan information from the AIRS API and applies a heuristic scoring model to prioritize findings that deserve closer inspection.

---

# Prerequisites

Before running the script:

1. Open **Prisma AIRS**.
2. Navigate to:

   ```
   Log Viewer → Filter: Prisma AIRS --> AI Runtime Security API
   ```
3. Export the scan logs as a **CSV** file.
4. Ensure the CSV contains:

   * `Scan ID`
   * `Verdict`

The script will automatically process only entries where the **Verdict** is **`malicious`**.

---

# What the Script Does

The analyzer performs the following workflow:

## 1. Read the Exported CSV

The script:

* Loads the exported CSV file.
* Filters all scan records whose **Verdict** equals **`malicious`**.
* Extracts the associated Scan IDs.

---

## 2. Query Prisma AIRS APIs

For every malicious Scan ID, the script retrieves additional information from two AIRS API endpoints.

### `/v1/scan/results`

Retrieves the detection results, including:

* Prompt Injection
* Toxic Content
* Data Loss Prevention (DLP)
* URL Filtering
* Malicious Code
* Source Code Detection
* Contextual Grounding

---

### `/v1/scan/reports`

Retrieves detailed metadata including:

* Detection confidence
* Detection categories
* Content snippets
* Supporting report information

---

## 3. False Positive Analysis

Each detection is evaluated using a heuristic scoring model that estimates how likely the result is to be a false positive.

The scoring considers several indicators.

### Confidence Level

Lower confidence detections receive a higher false-positive score.

Examples:

* Low confidence → Higher FP likelihood
* Moderate confidence → Possible FP
* High confidence → More likely to require review

---

### Business Context Detection

If the content contains common business terminology such as:

* management
* compliance
* deployment
* governance
* operations
* architecture

the script increases the false-positive likelihood since these often trigger benign detections.

---

### Toxic Content Validation

If:

* the **Toxic Content** detector is triggered,
* but no obvious toxic language exists in the content,

the script considers it more likely to be a false positive.

---

### Prompt Injection Validation

If:

* Prompt Injection is detected,
* but the content resembles a structured task (classification, summarization, extraction, translation, etc.),

the script increases the false-positive score.

---

### Snippet Length

Very short snippets frequently lack sufficient context.

Short content therefore increases the likelihood that a detection is a false positive.

---

# Output

The analyzer generates a CSV file named:

```
airs_malicious_violations.csv
```

Each row contains:

| Column          | Description                               |
| --------------- | ----------------------------------------- |
| Scan ID         | AIRS Scan Identifier                      |
| Direction       | Prompt or Response                        |
| Detection Flag  | Detection category triggered              |
| Confidence      | Detection confidence level                |
| FP Likelihood   | Likely FP / Possible FP / Review          |
| Reasoning       | Explanation of why the score was assigned |
| Snippet Preview | Portion of the analyzed content           |

---

# False Positive Ratings

| Rating          | Meaning                                                                                    |
| --------------- | ------------------------------------------------------------------------------------------ |
| **Likely FP**   | Strong indicators suggest the detection is a false positive.                               |
| **Possible FP** | Some indicators suggest a false positive; manual review is recommended.                    |
| **Review**      | Detection appears legitimate or lacks sufficient evidence to classify as a false positive. |

---

# Performance

To efficiently process large datasets, the script:

* Uses a **ThreadPoolExecutor** with **5 concurrent workers**
* Handles API rate limiting
* Automatically retries requests using **exponential backoff** when HTTP **429 (Too Many Requests)** responses are encountered

This significantly reduces processing time while remaining API-friendly.

---

# Typical Workflow

```text
Export AIRS Logs (CSV)
            │
            ▼
Read CSV
            │
            ▼
Filter Malicious Verdicts
            │
            ▼
Query /scan/results
            │
            ▼
Query /scan/reports
            │
            ▼
Apply False Positive Heuristics
            │
            ▼
Generate airs_malicious_violations.csv
```
