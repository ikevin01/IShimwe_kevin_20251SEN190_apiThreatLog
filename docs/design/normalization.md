# Database Normalization (UNF → 3NF) & Raw Field Mapping

## 1. Target Normalized Entities (3NF Overview)
To eliminate repeating groups, duplicate metric columns, and transitive dependencies from the raw 29-column Burp Suite web traffic CSV, the schema is decomposed into **5 related tables** in Third Normal Form (3NF) for `ishimwe_kevindb`:

1. **`API_ENDPOINTS`** — Stores unique HTTP method and URI path combinations along with path length and sensitivity classification.
2. **`REQUEST_LOGS`** — Stores each atomic HTTP request event, referencing `API_ENDPOINTS`, with cleaned request body byte length and audit timestamp.
3. **`REQUEST_LEXICAL_METRICS`** — Stores decomposed atomic lexical and character-frequency inspection metrics (URL vs. body) per request log (`1:1` extension table).
4. **`SECURITY_THREATS`** — Stores threat classifications, calculated risk scores, and detection statuses for requests flagged as suspicious or malicious (`class = 1` or `prediction = 1`).
5. **`IP_QUARANTINE_LIST`** — Stores automated containment/quarantine actions triggered by high-risk security threats.

---

## 2. Step-by-Step Normalization Using Real Dataset Rows

### Sample Raw Records Selected (Rows 1–4 from `data/raw/test traficct new.csv`)
* **Row 1:** `method='POST'`, `path='/doLogin'`, `url_badwords=1`, `path_length=8`, `body_length=33`, `class=1`, `features='[0, 0, 0, 0, 0, 0, 0, 0, 2, 8, 33, 0]'`, `prediction=0`
* **Row 2:** `method='POST'`, `path='/sendFeedback'`, `url_spaces=7`, `path_length=13`, `body_length=124`, `class=1`, `features='[0, 0, 0, 0, 7, 0, 0, 0, 5, 13, 124, 0]'`, `prediction=1`
* **Row 3:** `method='GET'`, `path='/admin/clients.xls'`, `url_badwords=1`, `path_length=18`, `body_length=0`, `class=1`, `features='[0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 3, 0]'`, `prediction=0`
* **Row 4:** `method='GET'`, `path='/my%20documents/JohnSmith/Bank%20Site%20Documents/grouplife.htm'`, `url_spaces=3`, `path_length=57`, `body_length=0`, `class=1`, `features='[0, 0, 0, 0, 3, 0, 0, 0, 0, 57, 3, 0]'`, `prediction=1`

---

### Stage 0: Unnormalized Form (UNF)
In UNF, each raw CSV row contains **duplicate column headers** (`single_q`..`badwords_count` repeated twice) and a **multi-valued list column (`features`)** storing 12 comma-separated numeric values inside a single cell.

| raw_row_id | method | path | url_spaces | url_badwords | path_length | body_length | features (Repeating Group) | class | prediction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | POST | `/doLogin` | 0 | 1 | 8 | 33 | `[0, 0, 0, 0, 0, 0, 0, 0, 2, 8, 33, 0]` | 1 | 0 |
| 2 | POST | `/sendFeedback` | 7 | 0 | 13 | 124 | `[0, 0, 0, 0, 7, 0, 0, 0, 5, 13, 124, 0]` | 1 | 1 |
| 3 | GET | `/admin/clients.xls` | 0 | 1 | 18 | 0 | `[0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 3, 0]` | 1 | 0 |
| 4 | GET | `/my%20documents/JohnSmith/.../grouplife.htm` | 3 | 0 | 57 | 0 | `[0, 0, 0, 0, 3, 0, 0, 0, 0, 57, 3, 0]` | 1 | 1 |

---

### Stage 1: First Normal Form (1NF)
* **Dependency Removed:** Removed the repeating group in `features` (and disambiguated the 12 duplicate lexical column headers into distinct `url_*` and `body_*` atomic attributes) so every cell holds a single scalar value and each row is uniquely identified by `log_id`.

| log_id (PK) | method | path | path_length | body_length | url_spaces | url_badwords | feat_special_chars | feat_payload_len | class | prediction |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | POST | `/doLogin` | 8 | 33 | 0 | 1 | 2 | 33 | 1 | 0 |
| 2 | POST | `/sendFeedback` | 13 | 124 | 7 | 0 | 5 | 124 | 1 | 1 |
| 3 | GET | `/admin/clients.xls` | 18 | 0 | 0 | 1 | 0 | 3 | 1 | 0 |
| 4 | GET | `/my%20documents/USER_REDACTED/.../grouplife.htm` | 57 | 0 | 3 | 0 | 0 | 3 | 1 | 1 |

---

### Stage 2: Second Normal Form (2NF)
* **Dependency Removed:** Removed partial dependencies where endpoint attributes (`http_method`, `endpoint_path`, `path_length`, `url_spaces`, `url_badwords`) depend only on the endpoint identity `(http_method, endpoint_path)` rather than the individual request execution `log_id`, moving endpoint definitions into `API_ENDPOINTS`.

**Table: `API_ENDPOINTS`**

| endpoint_id (PK) | http_method | endpoint_path | path_length | sensitivity_level |
| :--- | :--- | :--- | :--- | :--- |
| 101 | POST | `/doLogin` | 8 | CRITICAL |
| 102 | POST | `/sendFeedback` | 13 | MEDIUM |
| 103 | GET | `/admin/clients.xls` | 18 | CRITICAL |
| 104 | GET | `/my%20documents/USER_REDACTED/Bank%20Site%20Documents/grouplife.htm` | 57 | HIGH |

**Table: `REQUEST_LOGS` (2NF)**

| log_id (PK) | endpoint_id (FK) | body_length | class | prediction |
| :--- | :--- | :--- | :--- | :--- |
| 1 | 101 | 33 | 1 | 0 |
| 2 | 102 | 124 | 1 | 1 |
| 3 | 103 | 0 | 1 | 0 |
| 4 | 104 | 0 | 1 | 1 |

---

### Stage 3: Third Normal Form (3NF)
* **Dependency Removed:** Removed transitive dependencies where threat classification (`threat_type`, `risk_score`, `model_prediction`) depends on `actual_class` rather than `log_id`, where quarantine enforcement (`quarantine_id`, `block_reason`, `quarantine_status`) depends on `threat_id`, and where detailed lexical inspection counts are isolated in `REQUEST_LEXICAL_METRICS`.

**1. `API_ENDPOINTS`**

| endpoint_id (PK) | http_method | endpoint_path | path_length | sensitivity_level |
| :--- | :--- | :--- | :--- | :--- |
| 101 | POST | `/doLogin` | 8 | CRITICAL |
| 102 | POST | `/sendFeedback` | 13 | MEDIUM |
| 103 | GET | `/admin/clients.xls` | 18 | CRITICAL |
| 104 | GET | `/my%20documents/USER_REDACTED/Bank%20Site%20Documents/grouplife.htm` | 57 | HIGH |

**2. `REQUEST_LOGS`**

| log_id (PK) | endpoint_id (FK) | source_ip | body_length | http_status | logged_at |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | 101 | 192.168.10.14 | 33 | 401 | 2026-11-21 15:01:10 |
| 2 | 102 | 192.168.10.22 | 124 | 403 | 2026-11-21 15:01:14 |
| 3 | 103 | 10.0.5.88 | 0 | 403 | 2026-11-21 15:01:19 |
| 4 | 104 | 172.16.4.9 | 0 | 403 | 2026-11-21 15:01:25 |

**3. `REQUEST_LEXICAL_METRICS`**

| metric_id (PK) | log_id (FK) | url_single_q | url_double_q | url_dashes | url_spaces | url_badwords | body_special_chars | body_badwords |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 501 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 1 |
| 502 | 2 | 0 | 0 | 0 | 7 | 0 | 0 | 0 |
| 503 | 3 | 0 | 0 | 0 | 0 | 1 | 0 | 1 |
| 504 | 4 | 0 | 0 | 0 | 3 | 0 | 0 | 0 |

**4. `SECURITY_THREATS`**

| threat_id (PK) | log_id (FK) | threat_type | actual_class | model_prediction | risk_score | detected_at |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 9001 | 1 | CREDENTIAL_PROBING | 1 | 0 | 65 | 2026-11-21 15:01:10 |
| 9002 | 2 | PAYLOAD_INJECTION | 1 | 1 | 88 | 2026-11-21 15:01:14 |
| 9003 | 3 | SENSITIVE_FILE_ACCESS | 1 | 0 | 72 | 2026-11-21 15:01:19 |
| 9004 | 4 | UNAUTHORIZED_PATH_TRAVERSAL | 1 | 1 | 85 | 2026-11-21 15:01:25 |

**5. `IP_QUARANTINE_LIST`**

| quarantine_id (PK) | threat_id (FK) | blocked_ip | block_reason | is_active | quarantined_at |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 301 | 9002 | 192.168.10.22 | Risk score 88 exceeded threshold (75) on /sendFeedback | Y | 2026-11-21 15:01:14 |
| 302 | 9004 | 172.16.4.9 | Risk score 85 exceeded threshold (75) on sensitive document path | Y | 2026-11-21 15:01:25 |

---

## 3. Raw-to-Target Field Mapping & Phase IV Cleaning Checklist

Every column from `data/raw/test traficct new.csv` is accounted for below:

| Raw Col # | Raw Column Name | Target Table | Target Column | Phase IV Transformation / Cleaning Rule |
| :--- | :--- | :--- | :--- | :--- |
| 1 | `method` | `API_ENDPOINTS` | `http_method` | Convert `'0'` placeholders (406 rows) to `'UNKNOWN'`; uppercase & trim text. |
| 2 | `path` | `API_ENDPOINTS` | `endpoint_path` | Convert `'0'` placeholders (406 rows) to `'/unknown'`; mask `JohnSmith` (29 rows) to `USER_REDACTED`. |
| 3 | `single_q` (1st) | `REQUEST_LEXICAL_METRICS` | `url_single_q` | Cast text to `NUMBER`; counts single quotes (`'`) in URI path. |
| 4 | `double_q` (1st) | `REQUEST_LEXICAL_METRICS` | `url_double_q` | Cast text to `NUMBER`; counts double quotes (`"`) in URI path. |
| 5 | `dashes` (1st) | `REQUEST_LEXICAL_METRICS` | `url_dashes` | Cast text to `NUMBER`; counts SQL comment dashes (`--`) in URI path. |
| 6 | `braces` (1st) | `REQUEST_LEXICAL_METRICS` | `url_braces` | Cast text to `NUMBER`; counts curly braces (`{}`) in URI path. |
| 7 | `spaces` (1st) | `REQUEST_LEXICAL_METRICS` | `url_spaces` | Cast text to `NUMBER`; counts encoded/raw spaces in URI path. |
| 8 | `percentages` (1st) | `REQUEST_LEXICAL_METRICS` | `url_percentages` | Cast text to `NUMBER`; counts URL encoding `%` characters in URI path. |
| 9 | `semicolons` (1st) | `REQUEST_LEXICAL_METRICS` | `url_semicolons` | Cast text to `NUMBER`; counts statement-chaining `;` in URI path. |
| 10 | `angle_brackets` (1st) | `REQUEST_LEXICAL_METRICS` | `url_angle_brackets` | Cast text to `NUMBER`; counts XSS `<` and `>` characters in URI path. |
| 11 | `special_chars` (1st) | `REQUEST_LEXICAL_METRICS` | `url_special_chars` | Cast text to `NUMBER`; counts special symbols in URI path. |
| 12 | `path_length` (1st) | `API_ENDPOINTS` | `path_length` | Cast text to `NUMBER`; validate against `LENGTH(endpoint_path)`. |
| 13 | `body_length` (1st) | `REQUEST_LOGS` | `body_length` | Cast text to `NUMBER`; represents HTTP request payload byte size. |
| 14 | `badwords_count` (1st) | `REQUEST_LEXICAL_METRICS` | `url_badwords` | Cast text to `NUMBER`; counts SQLi keywords (`select`, `sleep`, `uid`, `waitfor`, `delay`) in URI path. |
| 15–23 | `single_q`..`special_chars` (2nd) | `REQUEST_LEXICAL_METRICS` | `body_single_q`..`body_special_chars` | Disambiguate duplicated headers as body-level lexical counts; cast text to `NUMBER`. |
| 24 | `path_length` (2nd) | *DROPPED* | — | Redundant duplicate of column 12 (`path_length`); eliminated to avoid update anomalies. |
| 25 | `body_length` (2nd) | *DROPPED* | — | Redundant duplicate of column 13 (`body_length`); eliminated in 3NF. |
| 26 | `badwords_count` (2nd) | `REQUEST_LEXICAL_METRICS` | `body_badwords` | Disambiguate duplicated header as body-level SQLi keyword count; cast text to `NUMBER`. |
| 27 | `class` | `SECURITY_THREATS` | `actual_class` | Cast `'0'`/`'1'` text to `NUMBER(1)`; filter rows with `class = 1` or `prediction = 1` into `SECURITY_THREATS`. |
| 28 | `features` | *DECOMPOSED / DROPPED* | — | 12-element JSON array string decomposed in 1NF; elements 1–8 and 10–12 duplicate columns 15–26, while element 9 maps to `body_special_chars`. |
| 29 | `prediction` | `SECURITY_THREATS` | `model_prediction` | Cast `'0'`/`'1'` text to `NUMBER(1)`; used by PL/SQL `FNC_CALCULATE_RISK_SCORE` to compute `risk_score`. |