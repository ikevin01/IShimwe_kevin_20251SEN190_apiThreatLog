# Dataset Card — Web Network HTTP Traffic & Threat Logs

## 1. Dataset Metadata
* **Dataset Name:** Web Network (`test traficct new.csv`)
* **Raw File Path:** `data/raw/test traficct new.csv` (stored untouched as downloaded)
* **Source URL:** https://www.kaggle.com/datasets/willianoliveiragibin/web-network
* **Author / Publisher:** Willian Oliveira (`willianoliveiragibin`)
* **License:** CC0: Public Domain (Kaggle Open Dataset)
* **File Format:** CSV (Comma-Separated Values, UTF-8 encoded)
* **File Size:** 57,446 bytes (56.10 KB)
* **Record Count:** 522 data rows (523 lines including header row; satisfies the $\ge 500$ record requirement)
* **Column Count:** 29 columns total (17 unique column names; 12 duplicated column names)
* **Date Collected / Downloaded:** November 21, 2026 (Dataset updated on Kaggle in September 2024)
* **Unit of Observation:** Each row represents one captured HTTP/web API request intercepted by Burp Suite, recording its HTTP method, target URI path, lexical character frequencies (URL vs. request body), payload lengths, SQL injection/bad-word keyword counts, ground-truth threat label (`class`), serialized feature vector (`features`), and model threat prediction (`prediction`).

---

## 2. Privacy & Anonymization Audit
* **Personal Identifiers Found:** 29 rows contain the hardcoded sample username `JohnSmith` inside URL directory paths (e.g., `/my%20documents/JohnSmith/Bank%20Site%20Documents/grouplife.htm`). No real customer names, national IDs, phone numbers, email addresses, or live IP addresses exist in the raw file.
* **Action Taken:** Per Phase II rules, `data/raw/test traficct new.csv` is preserved completely unmodified. During Phase IV ETL cleaning, the string `JohnSmith` in URL paths will be masked/anonymized to `USER_REDACTED`.

---

## 3. Data Quality Assessment (Exact Issue Counts)
All quality checks below were executed read-only against `data/raw/test traficct new.csv`. No values have been altered in Phase II; these counts form the cleaning checklist for Phase IV.

| Quality Dimension | Finding / Anomaly Description | Exact Count / Metric | Phase IV Remediation Plan |
| :--- | :--- | :--- | :--- |
| **Duplicate Columns** | Columns 3–14 (`single_q` through `badwords_count`) share identical header names with columns 15–26. The first set measures URL-path lexical counts while the second set measures body/payload lexical counts. | **12** duplicated column names (**1,506** total cell-level value differences between the two sets) | Rename columns 3–14 with prefix `url_*` and columns 15–26 with prefix `body_*` (and split into normalized child/metric attributes). |
| **Exact Duplicate Rows** | Identical rows repeated verbatim across all 29 columns (primarily rows with placeholder `0` method/path values). | **250** duplicate rows (leaving **272** unique records) | Deduplicate records during Phase IV staging and enforce `UNIQUE` / primary key constraints. |
| **Placeholder / Missing Semantics** | Instead of `NULL`, missing HTTP methods and URI paths are encoded as the string `'0'`. | **406** rows with `method = '0'` (77.78%) and **406** rows with `path = '0'` (77.78%); **0** literal empty/NULL cells | Map `'0'` to `'UNKNOWN'` in `API_ENDPOINTS` (`http_method = 'UNKNOWN'`, `endpoint_path = '/unknown'`). |
| **Nested / Multi-Valued Field** | The `features` column stores a 12-element numeric array serialized as a single text string (e.g., `[0, 0, 0, 0, 0, 0, 0, 0, 2, 8, 33, 0]`). | **522** rows contain serialized list strings (**0** malformed bracket strings) | Decompose repeating array elements into atomic columns (`1NF`) and eliminate redundant derived counts in `3NF`. |
| **Data Types Stored as Text** | All numeric metrics (`path_length`, `body_length`, character counts) and binary flags (`class`, `prediction`) are stored as raw CSV text strings. | **26** numeric/flag columns stored as text across all **522** rows | Cast counts and lengths to Oracle `NUMBER` and map `0`/`1` flags to `NUMBER(1)` or `CHAR(1)` in Phase IV. |
| **PII Exposure in Paths** | Sample personal identifier `JohnSmith` embedded in URI path strings. | **29** rows (5.56%) | Replace `JohnSmith` with `USER_REDACTED` during Phase IV ETL sanitization. |
| **Class & Prediction Distribution** | Binary target `class` (`0` = benign, `1` = malicious) vs. `prediction` (`0` = benign, `1` = flagged threat). | `class`: **287** benign (`0`), **235** malicious (`1`)<br>`prediction`: **321** benign (`0`), **201** flagged (`1`) | Load into `SECURITY_THREATS` and compute risk scores (`0–100`) via PL/SQL function `FNC_CALCULATE_RISK_SCORE`. |