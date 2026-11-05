# IShimwe_kevin_20251SEN190_apiThreatLog

 Automated API Threat Detection and Security Anomaly Logging Engine

**Student Name:** Ishimwe Kevin  
**Student ID:** 20251SEN190  
**Course:** INSY 8311 – Database Development with PL/SQL  
**Instructor:** Eric Maniraguha  
**Institution:** Adventist University of Central Africa (AUCA)  
**Academic Year:** 2026–2027 (Semester I)  

---

## 1. Project Overview & Problem Statement

Modern enterprise web backends and API gateways process millions of incoming requests daily. However, web application firewalls and APIs frequently encounter severe threats, including distributed rate-limit abuse, credential stuffing, SQL injection attempt signatures, and unauthorized endpoint probing. Managing these security risks purely at the application layer can lead to delayed threat mitigation, unlogged security breaches, and heavy processing overhead on backend services.

This project implements an autonomous, **Database-Level API Threat Detection and Security Anomaly Logging Engine** using Oracle PL/SQL. By anchoring threat evaluation directly inside the pluggable database (`ishimwe_kevindb`), security rules are enforced at the data level. The system automatically ingests web API access logs, evaluates client risk metrics using PL/SQL packages, dynamically flags suspicious activity, and instantly quarantines malicious IP addresses via automated triggers.

---

## 2. Project Objectives

### Main Objective
To design and deploy a robust Oracle PL/SQL database system capable of processing real-time API logs, evaluating security risk factors, and automatically quarantining malicious IP addresses.

### Specific Objectives
1. **Database Architecture:** Design and normalize a 3rd Normal Form (3NF) database schema to store API client credentials, endpoint metadata, incoming request logs, threat incidents, and quarantine records.
2. **Automated Threat Detection:** Develop PL/SQL packages (`PKG_API_SECURITY`) containing procedures and functions to calculate rolling risk scores based on request frequency and HTTP status codes.
3. **Dynamic Defense Mechanics:** Implement row-level and statement-level triggers to intercept rate-limit violations and auto-populate an IP quarantine registry.
4. **Security Auditing:** Configure fine-grained database auditing (`FGA`) and custom log triggers to record administrative actions and unauthorized access attempts.
5. **Interactive Innovation:** Build a live, real-time Security Monitoring Dashboard (Grafana / Oracle Enterprise Manager) connected directly to the Oracle database to visualize threat metrics, active quarantines, and rate-limit violations.

---

## 3. Data Source

* **Dataset Name:** Cybersecurity Threat Detection Logs
* **Source:** Kaggle
* **URL:** [https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs](https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs)
* **Dataset Characteristics:** The dataset comprises over 100,000 HTTP/network security logs formatted as CSV. It includes key attributes such as `timestamp`, `source_ip`, `request_path`, `http_method`, `response_code`, `payload_bytes`, and `threat_classification`.
* **Usage:** Preprocessed and imported into the Oracle database to populate the `REQUEST_LOGS` table for testing PL/SQL threat detection procedures, triggers, and live dashboard metrics.

---

## 4. Planned Database Schema (3NF Target)

1. `API_CLIENTS` (`client_id`, `client_name`, `api_key_hash`, `status`, `created_at`)
2. `API_ENDPOINTS` (`endpoint_id`, `path`, `http_method`, `rate_limit_per_min`, `risk_level`)
3. `REQUEST_LOGS` (`log_id`, `client_id`, `endpoint_id`, `ip_address`, `response_code`, `request_time`, `payload_bytes`)
4. `SECURITY_THREATS` (`threat_id`, `log_id`, `ip_address`, `threat_type`, `severity_score`, `detected_at`)
5. `IP_QUARANTINE_LIST` (`quarantine_id`, `ip_address`, `reason`, `blocked_until`, `is_active`)

---

## 5. Planned PL/SQL Features

* **Packages (`PKG_API_SECURITY`):** Encapsulates API logging subprograms, security policy settings, and IP quarantine logic.
* **Procedures:** 
  * `PRC_LOG_API_REQUEST`: Ingests incoming API call metrics into the database.
  * `PRC_QUARANTINE_IP`: Inserts malicious IPs into the lock list and revokes active API client tokens.
* **Functions:** 
  * `FNC_CALCULATE_RISK_SCORE`: Evaluates request frequency and failure rates over a rolling window to return a risk index ($0 - 100$).
* **Triggers:**
  * `TRG_DETECT_ANOMALY`: `AFTER INSERT` trigger on `REQUEST_LOGS` that automatically detects rate-limit breaches or error spikes and flags threat entries.
  * `TRG_ENFORCE_QUARANTINE`: `BEFORE INSERT` trigger that blocks request insertion if the originating IP resides on `IP_QUARANTINE_LIST`.
* **Cursors:** Explicit cursors within batch maintenance tasks to clear expired quarantines and generate daily security reports.
* **Audit Logs & Triggers:** Custom security audit tables capturing administrative overrides and denied connections.

---

## 6. Planned Innovation (Security Monitoring)

* **Innovation Type:** Security Monitoring Dashboard
* **Tool Stack:** Grafana / Oracle Enterprise Manager (OEM)
* **Description:** A live interactive security dashboard connected directly to the Oracle database via SQL/JDBC connector. 
* **Key Features Displayed:**
  * Real-time attack volume trends and request spikes per minute.
  * Total active IP quarantines and geographic origin distribution.
  * Live stream of database security audit logs (`SECURITY_THREATS`).
  * Dynamic alerts when threat severity thresholds are breached.

---

## 7. Repository Structure

```text
Ishimwe_kevin_20251SEN190_apiThreatLog/
├── README.md
├── docs/
│   ├── research/
│   │   └── research_log.md
│   ├── proposal/
│   │   └── proposal.pdf
│   ├── presentation/
│   └── architecture/
├── data/
│   ├── raw/
│   └── scripts/
├── sql/
│   ├── ddl/
│   ├── dml/
│   ├── plsql/
│   └── triggers/
└── innovation/
    ├── dashboard_config/
    └── screenshots/
```

---

## 8. References (APA)

* Aryan, S. (2024). *Cybersecurity Threat Detection Logs Dataset*. Kaggle. https://www.kaggle.com/datasets/aryan208/cybersecurity-threat-detection-logs
* Oracle Corporation. (2023). *Database PL/SQL Language Reference (19c)*. Oracle Documentation. https://docs.oracle.com/en/database/oracle/oracle-database/19/lnpls/
* Stallings, W. (2018). *Network Security Essentials: Applications and Standards* (6th ed.). Pearson.
* * Al-Mhiqani, M. N., et al. (2020). Cyber-threat detection and mitigation in API gateways: A review. *IEEE Access*, 8, 120412-120426.
* Amazon Web Services. (2025). *AWS WAF Developer Guide: Rate-based rules and IP reputation list enforcement*. AWS Documentation.
* Aryan, S. (2024). *Cybersecurity Threat Detection Logs Dataset*. Kaggle.
* Gupta, S., & Kumar, R. (2022). Automated IP quarantine and threat mitigation architectures in enterprise relational databases. *Journal of Cybersecurity Technology*, 6(3), 145-162.
* Oracle Corporation. (2024). *Database PL/SQL Language Reference (19c / 21c)*. Oracle Documentation.
* OWASP Foundation. (2023). *OWASP API Security Top 10 2023*. OWASP.
