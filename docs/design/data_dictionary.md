# Logical Data Dictionary — API Threat Detection & Anomaly Logging Engine

> **Note:** Per Phase II logical design guidelines, physical Oracle data types and column lengths are omitted here and will be defined during Phase IV physical implementation.

---

## 1. Entity: `API_ENDPOINTS`
Stores normalized HTTP endpoint routes and methods accessed by incoming requests.

| Column Name | Key | Business Meaning | Required | Unique |
| :--- | :--- | :--- | :--- | :--- |
| `endpoint_id` | PK | Surrogate unique identifier assigned to each distinct API/web endpoint. | Yes | Yes |
| `http_method` | — | HTTP request verb (`GET`, `POST`, or `UNKNOWN` for raw `'0'` placeholders). | Yes | No |
| `endpoint_path` | — | Normalized URI path requested by the client (anonymized for PII). | Yes | No |
| `path_length` | — | Character length of the URI path string. | Yes | No |
| `sensitivity_level` | — | Security criticality classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) used in risk scoring. | Yes | No |

*(Composite uniqueness enforced on `(http_method, endpoint_path)`.)*

---

## 2. Entity: `REQUEST_LOGS`
Core audit log capturing each incoming HTTP request passing through the API gateway.

| Column Name | Key | Business Meaning | Required | Unique |
| :--- | :--- | :--- | :--- | :--- |
| `log_id` | PK | Surrogate unique identifier for each logged HTTP request event. | Yes | Yes |
| `endpoint_id` | FK | References `API_ENDPOINTS(endpoint_id)` identifying the targeted route and method. | Yes | No |
| `source_ip` | — | Originating client IPv4/IPv6 address assigned by the gateway simulator. | Yes | No |
| `body_length` | — | Size of the HTTP request body payload in bytes (`0` for bodyless GET requests). | Yes | No |
| `http_status` | — | HTTP response status code returned by the gateway (`200`, `401`, `403`). | Yes | No |
| `logged_at` | — | Exact date and time when the request was captured by the gateway. | Yes | No |

---

## 3. Entity: `REQUEST_LEXICAL_METRICS`
Stores character-level and keyword anomaly counts extracted from the URI path and HTTP request body.

| Column Name | Key | Business Meaning | Required | Unique |
| :--- | :--- | :--- | :--- | :--- |
| `metric_id` | PK | Surrogate unique identifier for the lexical inspection record. | Yes | Yes |
| `log_id` | FK | References `REQUEST_LOGS(log_id)` in a one-to-one (`1:1`) relationship. | Yes | Yes |
| `url_single_q` | — | Count of single-quote (`'`) characters detected in the URI path. | Yes | No |
| `url_double_q` | — | Count of double-quote (`"`) characters detected in the URI path. | Yes | No |
| `url_dashes` | — | Count of dash (`-`) characters detected in the URI path. | Yes | No |
| `url_braces` | — | Count of curly-brace (`{`, `}`) characters detected in the URI path. | Yes | No |
| `url_spaces` | — | Count of space characters detected in the URI path. | Yes | No |
| `url_percentages` | — | Count of percent-encoding (`%`) characters detected in the URI path. | Yes | No |
| `url_semicolons` | — | Count of semicolon (`;`) characters detected in the URI path. | Yes | No |
| `url_angle_brackets` | — | Count of angle-bracket (`<`, `>`) characters detected in the URI path. | Yes | No |
| `url_special_chars` | — | Count of non-alphanumeric special characters in the URI path. | Yes | No |
| `url_badwords` | — | Count of malicious SQLi keywords (`select`, `sleep`, `uid`, `waitfor`, `delay`) in the URI path. | Yes | No |
| `body_single_q` | — | Count of single-quote (`'`) characters detected in the request body. | Yes | No |
| `body_double_q` | — | Count of double-quote (`"`) characters detected in the request body. | Yes | No |
| `body_dashes` | — | Count of dash (`-`) characters detected in the request body. | Yes | No |
| `body_braces` | — | Count of curly-brace characters detected in the request body. | Yes | No |
| `body_spaces` | — | Count of space characters detected in the request body. | Yes | No |
| `body_percentages` | — | Count of percent (`%`) characters detected in the request body. | Yes | No |
| `body_semicolons` | — | Count of semicolon (`;`) characters detected in the request body. | Yes | No |
| `body_angle_brackets` | — | Count of angle-bracket (`<`, `>`) characters detected in the request body. | Yes | No |
| `body_special_chars` | — | Count of non-alphanumeric special characters in the request body. | Yes | No |
| `body_badwords` | — | Count of malicious SQLi keywords detected in the request body. | Yes | No |

---

## 4. Entity: `SECURITY_THREATS`
Records suspicious or malicious requests identified by ground-truth labels, classifier predictions, or PL/SQL anomaly triggers.

| Column Name | Key | Business Meaning | Required | Unique |
| :--- | :--- | :--- | :--- | :--- |
| `threat_id` | PK | Surrogate unique identifier for each detected security threat event. | Yes | Yes |
| `log_id` | FK | References `REQUEST_LOGS(log_id)` identifying the offending HTTP request. | Yes | Yes |
| `threat_type` | — | Categorized attack vector (`SQL_INJECTION`, `XSS_PROBE`, `SENSITIVE_FILE_ACCESS`, `PAYLOAD_INJECTION`). | Yes | No |
| `actual_class` | — | Ground-truth classification label from the raw dataset (`0` = Benign, `1` = Malicious). | Yes | No |
| `model_prediction` | — | Upstream classifier prediction flag (`0` = Normal, `1` = Threat). | Yes | No |
| `risk_score` | — | Composite threat severity score (`0` to `100`) calculated by PL/SQL logic. | Yes | No |
| `detected_at` | — | Timestamp when the anomaly trigger recorded the security alert. | Yes | No |

---

## 5. Entity: `IP_QUARANTINE_LIST`
Maintains active and historical IP address bans enforced automatically when threat risk scores exceed policy thresholds.

| Column Name | Key | Business Meaning | Required | Unique |
| :--- | :--- | :--- | :--- | :--- |
| `quarantine_id` | PK | Surrogate unique identifier for each IP quarantine enforcement action. | Yes | Yes |
| `threat_id` | FK | References `SECURITY_THREATS(threat_id)` that triggered the IP block. | Yes | No |
| `blocked_ip` | — | Quarantined client IP address denied access at the API gateway. | Yes | Yes |
| `block_reason` | — | Human-readable audit justification describing why the IP was quarantined. | Yes | No |
| `is_active` | — | Active enforcement flag (`Y` = Currently Blocked, `N` = Released/Expired). | Yes | No |
| `quarantined_at` | — | Timestamp when the quarantine block took effect. | Yes | No |
| `expires_at` | — | Scheduled timestamp when the temporary quarantine expires. | No | No |