import csv
import getpass
import os
import re
import sys
import requests
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# API Configuration
API_TOKEN = os.getenv("PANW_AI_SECURITY_TOKEN", "")

HEADERS = {
    "x-pan-token": API_TOKEN,
    "Content-Type": "application/json"
}

SCAN_RESULTS_URL = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/results"
SCAN_REPORTS_URL = "https://service.api.aisecurity.paloaltonetworks.com/v1/scan/reports"

CSV_OUTPUT_PATH = "airs_malicious_violations.csv"

MAX_WORKERS = 5
DELAY_BETWEEN_REQUESTS = 0.2
MAX_RETRIES = 5
INITIAL_BACKOFF = 4

SNIPPET_PREVIEW_LENGTH = 200

# Map scan result flag names to report detection_service values
FLAG_TO_SERVICE = {
    "injection": "pi",
    "toxic_content": "tc",
    "dlp": "dlp",
    "url_filtering": "uf",
    "malicious_code": "malicious_code",
    "source_code": "source_code",
    "contextual_grounding": "cg",
}

# Keywords that suggest the content is business/operational (not actually toxic or malicious)
BUSINESS_KEYWORDS = [
    "operations", "management", "banking", "payment", "technology", "infrastructure",
    "candidate", "taxonomy", "department", "organization", "org", "enterprise",
    "compliance", "finance", "services", "integration", "optimization", "commercial",
    "security", "network", "deployment", "configuration", "policy", "report",
    "customer", "account", "project", "workflow", "process", "analytics",
]

# Keywords that indicate genuinely toxic/malicious content
TOXIC_KEYWORDS = {
    "Hate": ["hate", "slur", "racial", "racist", "bigot", "discriminat", "supremac"],
    "Sexual Content": ["sexual", "explicit", "nude", "porn", "obscen", "erotic"],
    "Violence": ["kill", "murder", "attack", "bomb", "weapon", "shoot", "stab", "assault"],
    "Self-Harm": ["suicide", "self-harm", "cut myself", "end my life"],
    "Harassment": ["harass", "bully", "threaten", "stalk", "intimidat"],
}


def read_malicious_scan_ids(file_path):
    """Read CSV and return unique scan IDs where Verdict == malicious."""
    if not os.path.exists(file_path):
        print(f"Error: Input file '{file_path}' not found.")
        return []

    scan_ids = set()
    with open(file_path, mode='r', encoding='utf-8', errors='ignore') as f:
        reader = csv.reader(f)
        try:
            headers = [h.strip() for h in next(reader)]
            if "Scan ID" not in headers or "Verdict" not in headers:
                print("[-] CSV missing required 'Scan ID' or 'Verdict' columns.")
                return []
            id_idx = headers.index("Scan ID")
            verdict_idx = headers.index("Verdict")
            for row in reader:
                if row and len(row) > max(id_idx, verdict_idx):
                    s_id = row[id_idx].strip()
                    verdict = row[verdict_idx].strip().lower()
                    if s_id and verdict == "malicious":
                        scan_ids.add(s_id)
        except Exception as e:
            print(f"[-] CSV parsing error: {e}")
    return list(scan_ids)


def api_get_with_retry(url, params):
    """GET request with retry and backoff for 429s."""
    retry_delay = INITIAL_BACKOFF
    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, headers=HEADERS, params=params)
            if response.status_code == 429:
                print(f"    [Rate limited] Waiting {retry_delay}s before retry...")
                time.sleep(retry_delay)
                retry_delay *= 2
                continue
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"    [API Error] {url}: {e}")
            return None
    print(f"    [Failed] Max retries exceeded for {url}")
    return None


def get_report_details_by_service(report_id):
    """Call reports API and return structured details per malicious detection_service."""
    data = api_get_with_retry(SCAN_REPORTS_URL, {"report_ids": report_id})
    if not data or not isinstance(data, list) or len(data) == 0:
        return {}

    report = data[0]
    detection_results = report.get("detection_results", [])
    service_details = {}

    for service in detection_results:
        if service.get("verdict") == "malicious":
            detection_service = service.get("detection_service", "unknown")
            data_type = service.get("data_type", "")
            result_detail = service.get("result_detail", {})

            # Extract structured info
            info = {
                "confidence": "",
                "categories": [],
                "snippets": [],
                "raw_detail": result_detail,
            }

            if isinstance(result_detail, dict):
                for key, val in result_detail.items():
                    # Extract report blocks (tc_report, pi_report, etc.)
                    if isinstance(val, dict):
                        info["confidence"] = val.get("confidence", "")
                        cats = val.get("toxic_categories", [])
                        if cats:
                            info["categories"] = cats
                    # Extract snippet arrays
                    if "snippets" in key and isinstance(val, list):
                        info["snippets"] = val

            service_details[(detection_service, data_type)] = info

    return service_details


def assess_fp_likelihood(flag_name, confidence, categories, snippet_text):
    """Determine false positive likelihood based on confidence, categories, and snippet content."""
    reasons = []
    score = 0  # higher = more likely FP

    # 1. Confidence level check
    if confidence == "low":
        score += 3
        reasons.append("Low confidence")
    elif confidence == "moderate":
        score += 2
        reasons.append("Moderate confidence")
    elif confidence == "high":
        score -= 1

    # 2. Check if snippet contains business/operational keywords
    snippet_lower = snippet_text.lower()
    business_matches = [kw for kw in BUSINESS_KEYWORDS if kw in snippet_lower]
    if len(business_matches) >= 2:
        score += 2
        reasons.append(f"Business context detected ({', '.join(business_matches[:3])})")

    # 3. For toxic content: check if snippet actually contains toxic keywords for the flagged category
    if flag_name == "toxic_content" and categories:
        has_toxic_match = False
        for cat in categories:
            cat_keywords = TOXIC_KEYWORDS.get(cat, [])
            if any(kw in snippet_lower for kw in cat_keywords):
                has_toxic_match = True
                break
        if not has_toxic_match:
            score += 3
            reasons.append(f"No '{'/'.join(categories)}' keywords found in content")

    # 4. For prompt injection: check if it looks like a structured internal prompt
    if flag_name == "injection":
        structural_patterns = [
            r"candidate\s+taxonomy", r"\[org\]", r"which\s+numbers?\s+is",
            r"classify", r"categorize", r"chunk:\s*\n",
        ]
        structural_matches = [p for p in structural_patterns if re.search(p, snippet_lower)]
        if structural_matches:
            score += 3
            reasons.append("Looks like structured internal prompt/classification task")

    # 5. Short or gibberish snippets are suspicious detections
    if len(snippet_text.strip()) < 10:
        score += 2
        reasons.append(f"Very short snippet ({len(snippet_text.strip())} chars)")

    # Determine likelihood
    if score >= 4:
        likelihood = "Likely FP"
    elif score >= 2:
        likelihood = "Possible FP"
    else:
        likelihood = "Review"

    return likelihood, "; ".join(reasons) if reasons else "No FP indicators"


def process_single_scan(s_id):
    """For a scan ID: get scan results, find true flags, return one row per true flag with FP analysis."""
    time.sleep(DELAY_BETWEEN_REQUESTS)

    data = api_get_with_retry(SCAN_RESULTS_URL, {"scan_ids": s_id})
    if not data or not isinstance(data, list) or len(data) == 0:
        return []

    item = data[0]
    result_block = item.get("result", {})

    prompt_flags = result_block.get("prompt_detected", {})
    response_flags = result_block.get("response_detected", {})
    report_id = result_block.get("report_id", f"R{s_id}")

    # Collect all flags that are True with their direction (prompt/response)
    true_flags = []
    if isinstance(prompt_flags, dict):
        for key, val in prompt_flags.items():
            if val is True:
                true_flags.append(("prompt", key))
    if isinstance(response_flags, dict):
        for key, val in response_flags.items():
            if val is True:
                true_flags.append(("response", key))

    if not true_flags:
        return []

    # Get report details keyed by (detection_service, data_type)
    service_details = get_report_details_by_service(report_id)

    # Build one row per true flag
    rows = []
    for direction, flag_name in true_flags:
        svc_key = FLAG_TO_SERVICE.get(flag_name, flag_name)
        # Look up by (detection_service, direction)
        details = service_details.get((svc_key, direction))
        if not details:
            # Fallback: match by detection_service regardless of direction
            for (svc, dt), d in service_details.items():
                if svc == svc_key:
                    details = d
                    break

        confidence = ""
        categories = []
        snippet_text = ""
        malicious_reason = "No detail in report"

        if details:
            confidence = details.get("confidence", "")
            categories = details.get("categories", [])
            snippets = details.get("snippets", [])
            snippet_text = " ".join(snippets) if snippets else ""

            # Build malicious reason from raw_detail
            raw = details.get("raw_detail", {})
            reason_parts = []
            for detail_key, detail_val in raw.items():
                if isinstance(detail_val, dict):
                    reason_parts.append(f"{detail_key} = {json.dumps(detail_val)}")
                elif isinstance(detail_val, list):
                    reason_parts.append(f"{detail_key} = {detail_val}")
                else:
                    reason_parts.append(f"{detail_key} = {detail_val}")
            malicious_reason = " | ".join(reason_parts) if reason_parts else "No detail in report"

        # Assess false positive likelihood
        fp_likelihood, fp_reasons = assess_fp_likelihood(flag_name, confidence, categories, snippet_text)

        # Truncate snippet for preview
        snippet_preview = snippet_text[:SNIPPET_PREVIEW_LENGTH].replace("\n", " ").strip()
        if len(snippet_text) > SNIPPET_PREVIEW_LENGTH:
            snippet_preview += "..."

        rows.append({
            "Scan ID": s_id,
            "Direction": direction,
            "Detection Flag": flag_name,
            "Confidence": confidence if confidence else "N/A",
            "Categories": ", ".join(categories) if categories else "N/A",
            "FP Likelihood": fp_likelihood,
            "FP Reasons": fp_reasons,
            "Snippet Preview": snippet_preview if snippet_preview else "N/A",
            "Report ID": report_id,
            "Malicious Reason": malicious_reason,
        })

    return rows


def main():
    global API_TOKEN, HEADERS

    if not API_TOKEN:
        API_TOKEN = getpass.getpass("Enter your PANW AI Security API token: ").strip()
        if not API_TOKEN:
            print("Error: API token is required.")
            return
        HEADERS["x-pan-token"] = API_TOKEN

    if len(sys.argv) > 1:
        csv_input = sys.argv[1]
    else:
        csv_input = input("Enter the path to the CSV file: ").strip().strip("'\"")

    if not os.path.exists(csv_input):
        print(f"Error: File '{csv_input}' not found.")
        return

    print(f"[*] Reading malicious scan IDs from: {csv_input}")
    scan_ids = read_malicious_scan_ids(csv_input)
    total_ids = len(scan_ids)

    if not total_ids:
        print("[-] No malicious scan IDs found. Exiting.")
        return

    print(f"[+] Found {total_ids} unique malicious scan IDs.")
    print(f"[*] Output file: {CSV_OUTPUT_PATH}")
    print("=" * 80)

    fieldnames = [
        "Scan ID", "Direction", "Detection Flag", "Confidence", "Categories",
        "FP Likelihood", "FP Reasons", "Snippet Preview", "Report ID", "Malicious Reason",
    ]

    with open(CSV_OUTPUT_PATH, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        processed_count = 0
        written_count = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(process_single_scan, s_id): s_id for s_id in scan_ids}

            for future in as_completed(futures):
                rows = future.result()
                processed_count += 1

                if rows:
                    for row in rows:
                        writer.writerow(row)
                        written_count += 1
                        print(f"    [{written_count}] {row['Direction']}_{row['Detection Flag']} | "
                              f"Confidence: {row['Confidence']} | "
                              f"FP: {row['FP Likelihood']} | "
                              f"Scan: {row['Scan ID'][:12]}...")
                else:
                    print(f"    [Skipped {processed_count}/{total_ids}] No true detection flags.")

    print(f"\n[*] Done. {written_count} rows written from {total_ids} scan IDs.")
    print(f"[*] Results saved to: {CSV_OUTPUT_PATH}")


if __name__ == "__main__":
    main()
