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

## Phase I: Business Process Modeling
- **Modeling Tool:** diagrams.net (draw.io)
- **Live Published Diagram:** [View Interactive BPMN Diagram]((https://viewer.diagrams.net/?tags=%7B%7D&lightbox=1&highlight=0000ff&edit=_blank&layers=1&nav=1&dark=auto#R%3Cmxfile%3E%3Cdiagram%20name%3D%22Page-1%22%20id%3D%22UcNUE84WrqK5HT0yQNzk%22%3E7Z1rd6I6F4B%2FjWud8%2BHMggBePiKCtbXqqJ2ZfupCicoZKj2Ibef99W8CAbkGVPBWurpaCTshZu88ue2EGie9fnYt9W31aGrQqAFG%2B6xxnRoAbLPeRP9wyB8SApokZGnpGgnbBUz0%2F0ESyJDQra7BTUjQNk3D1t%2FCgXNzvYZzOxSmWpb5ERZbmEb4qW%2FqEsYCJnPViIf%2B1DV7RULZemt34w7qyxV5dBM03BuvqidMvslmpWrmRyCIk2ucZJmm7X56%2FZSggUvPKxc3npJy18%2BYBdd2QoSnDbSGs39xmQDGUGdIMY4QyR20XlVd66i2SoIb7Rqo1wCHCp5DHxnnt%2F7fFmevrWE5%2F6rGiaG7C8P8mK9UCz%2BpP64J0tqL7%2F4Kzi%2FzzzE%2FqalOfvYe%2B%2BJARh9ZN2NSvycPpo6Mgv7Kv6byeCD20ceniXyi7G22syWuEbhEUObYmtBGIrsiY7%2FhjBo61p2f0U8bWmsVKxkrLyRfEzrxjO9%2BNd1CitZNLDBt0yTFv1BWJjZWllNYE7jW0L%2B76XSE%2Fo3hf1u4sdHT%2FqYl8oATkVFEJwkSl2c49LcD1zrUshLoJyUAGHxr%2BJAUGecSB53NtoCb1Z8yrhviqIf%2BdsWp%2FFN8PotBgahBAWxQP%2BFslzvVhh%2Fqn3KsCN1sS%2BqbvbVgwGoA8whtlbDCwA%2BcWY5p15f4ooeUjDLDjDAZyac%2Fhqlq7sUdVDVobTLyKKEn99bv5m%2FoGO98a%2Bn2H5yUZc6h5uQn4dGjsfTSH3ZfUNG8jOXvT%2FJkmvGcDgJib4M%2B4FwnpPh9q1rq2tbXyNg5pdagJiajTI8hKq11tLoopjXTNQ2uM7KjJKQQqC8XV104t7oMx6LUx9cdcSq2xQn%2BKA%2B6PUfmL32z0l8%2F4Mtv%2BK6vtVkCMU5Qk7hoTeJwTRpa6tzAJoZbyJm6wR%2Fl9RKpOyXjJVSyLsrZX8RasfVOcAx1ZiSbuDSWEY%2FcYu%2Bby121%2FDsjQ3foMYruVOSppS%2BXqOVJSn867r505KksTV%2FEwfBR7D9npNvDiH9XjS0CEc6NvvmNbWRuptRRZSC9SGJfeuqj7%2FEy7k0eXibScCxnPOYeVdTMtHf%2FmYaQXV8fUdZHY7H7iAtTfJoO0RcePk1epmNxMBGlaW84yNTBRJaexr3p88v0DodOMr7GwCGq08PDsPr%2BJKJnTVFFeUkB0NOo4z%2BrNwpG6Pcy6TZET3ONpI3a6yWWE5FRvmOW0mOOsFGizv5CXatO9disZqZqaYl5HMvTcU%2F%2B4Vml%2Fu5A27ag%2BppkleehljQcDGRHpxMnuK6%2BvrmmgqGF%2Fin94c%2FJaTIlOgkGrDUGiHZUQopKSFGJuD4j151wjIb0LE%2FQ35rTcGWIDoaupJL1EDmarYeohBKV6Gel6XzVb8Eo3ahIN5roXVTiLirRi0r0ohL3WRm7Ty3Rx0xRr0SHWQ95jGZrEJUYxMpnlC3SOUfPYfrc7w1iyiupA2D%2FcZp2XNkWOkIuphOnCbCp8agrurEt3Lt0Aptgxs53gf98uFMAInj7dFr65IT7ZSX8EEp40ZzD%2BTyS8Kwp8AKzb8Ly4Qmz1ISVw4uCnnA3nLAKm4tojuvzJpwt9i2KUVkJ34fLeLEAsTLW6rO6UN834U5ZCT8ebW67TjEe4qVOL83N9UJfRieY1lvcHaLFe0fjRacnnTYzxYJgFnbpNNyZMH8y7fukxUrP896PgbF4n9b5uxf%2Bv39Yf5LOn3wjs4xOJzw4txechSMTc24hOiFLy9ziLoWNRowbV7RtbtcanppkUTjUdLuHkiaXhjn%2FDbWuG6mD8%2BskMFI1TV8vsZBbFvgpqARs%2BBl4MMlvF5qv0LbwyFglM6BLP2g3SYg%2BkO%2FmXQamDanTiIeMkoIzjz1S8uhLi%2B4wLHi3jdKa7ApwZb8apHA%2BVroNJ2%2FqHN9amx9oJIdCXevzJmhZ1zRsfa4aooG7t1zHNrEctmbJNEzLSZdTFKUhd%2Fz4wTvtFkDlgWKYazsQzjg%2FJFxRX3UDT2yP8TzEBndv3RtkGpvlcdLetC%2FrXySl594ZLhYbaP9C9%2FhI2HMorG1sLWIbRAiVCO68c526bxuBsvyBhmHwSMVR6wqI15VgnUivX6GKUul5Pz07eTC3llNIK9t%2B26DuEkaggMdg6A8W2HxbmubSgOqbvvk2N1%2BdG%2FONI6os3K%2BGPoa%2BXG64rAJLHxxPaPgRWCjhWbIe4qXDNUhVJytCDZ4s1pSCqZTpE68hSJ00SWVVNyenkLrecOj8j4HqELQ4PDbG0Idaf%2BYJzdT5b8z2tTbc2gaufSQysSsmZvIgWjVIxYgYPOm2JBg86bvEDB40sQ1cusHTwHacqql04w6gG6DRrbKOMqzDqfd%2B4wA8fF8OIVm%2BlUBIPgRIwIfw2KqXicfYvK9XWxJme9OIeHdIzy2xPQdxU104P0mmGjLJqzNVGsj2VgqVXXzR7Kr0eE3IqTfixBFAuEvWAiHkoC5amcxJXxPy7Dx1JSgNQb0KQcUi6FgdUYkkVET6ykRqZhOJ89wGfa%2FBUomUYuKxReM0%2FNzT8GOtzNfZFuW7Hez%2FH9JtJzO7CRZLpnev1GKpg7p9VEOlTr0Q6lTavK45KcA0Y7Txw0gyAh8ectVLHXJl%2B5UkzVjEvEnSWPRYalfIXQJKsFmyDnSlNksjUJH6ogKqcRndohtV8cV3i9gEUkX7Rc06GyIV3yyTVBR3NM%2FkM5zQ0iA1qMZrxUKqIFVR%2BdS8DD7dqHZvgk8sE1ncY4VWmYRKc2FN486w4k6x3KEqgEqTVkWTr0yTHNPS0c4OYEodlyX7tHutJ8WTPZU2o5y0qRaDT42tI3VN9xpkiiZbZR9fEpF5nAVY4An5a3eldrgSWQexW5S%2Fg%2BAOa4xGPqgt%2FUvTslfm0lyrhrwLbVuucRN7QMX47ly4Jqxatoj39dewWyA2c9T70LyQGfaddYOIfTXR1b%2Fb1zfviao190KIAYIk2%2FZtDn7qjq2x5DO2Meab4DwDFesvki%2FnYncvXtNQvpfQHkFLR%2BqAFq5zrjMvn8GqPMhJ8FTGpRwwtT0Y5FWANDkuxqpKoykadUUoZcknY8CChmo76AgoMKlGO1FRUalBR%2B83U0eYilV4P%2F2yGHDnM6BXMeDkDACnZABfMaAwBgi3xICez4D7igEnZ0CCn3J5DBAqBhTGgPoVMgBvaU7DwL2PgcfbwkBgWB4cxPoDyrY%2FDA%2FEnjs%2FWQPipBF0so1yJ8SOr2U6eRK8jMsjT%2F3KyZNiRPxVG1HJkyeZCG2Ui1CS8ggH7OZfGk2QOP2i5JVnQITPbg6Kp%2FUgvPaVDOthBevC61mdVs%2F4VrG09rRMh3WCA3YF64uGdeFGdG5aB5d%2Fz0ZrEKZvtnyY7iXSOpXVjz6rB7fF6v1HY1zj9APsBCfy8sjZuHJynlKlmcAJeq%2BdDDgsw0f8oTKIE4%2FQOjtyBj5yRqUiR1M3K%2F8OvhipNj4Q2TEC5wDe9kL%2FxAv2NW%2FbxcUb9BnmABPcyMtDVLNYRFUmsA%2FSQp4m1zJrmHpOdRJ%2BvMOhAA06pR0axCgdRUyyBtDp8G0l3om%2FjkODaICha4cOnkP8w094BNSNavOyfJZ4Nn4EVEsgXRp%2Fcy8T7uI0Sz0BKuOYes%2FpL%2Bfh9GmUiteqyrP8yB0thauNjq9DHNLZeP%2Bn0vW1ulvm2N8SOZupLpQJrqy3XHhVIOndFmmYkipMFYupo5VEP1XzEF%2FyCkq3A6UcZ6U4b4EJQKlRLpT8V%2BJ4lh15EU4aeTo08lSnahzFoFw6oYMmwYP8ENBUiryu8Vqe41F4NrwK5m3xLekspozXZKXxRabxZa%2F2j00wxhs9FINGlVyKoEMFnKH38oW0d%2FG9lxybfBuNRgguHFvqkSapr9BLw4pSJlbI61ASDJO8E%2BVKDXMfrIQ1QOfJIcdwl8CTW1XbLfLEc%2FE59X7Ytr9oLn11P53Tr4GDQrzRfXJkLYKzrRhiKp0euqgNrnFROxUDko%2BBzlfAQB1cFgcKcXTOzQHvZWA3xoFylJoNgpQOQbkee1x0gwagb%2BiIyZP%2BR%2Fn%2BerTtdx0fO%2FJtYecidnQ0aBWCK3hHR779d6AQx%2BT8pIv77dyEHZ12U0fhdnTuTR2hCb%2BTIbsuhBfAvFX6NGTH5AnCU3eB8I2j5Dk%2BlJ%2Fz7PHbtQhK1SIUXpOpexqaxTYIubb4gUK8wKv24Kqt6OzNQXC%2B9nSb%2FDiB1iPPlEd8PxGuWexsLRk6dLKDnwgY%2BRPvd1BxfcXREnnuecWzNIqX5kfdUXhFSapMcrPRUlpxq78OP2oacnMris7kC3eQv1HFXtYSBifEHeSBN4HsHXwcOfeYK9XhYoLbWvLSEtSg7lbmst6ELObET7idT1pxQ601sRKBSWzmvsgCHI1B%2BdREB9BBZ65T108r3ebV7VUurjbYEJgi7u%2Flvn1GRkbumHvI%2F6gD1zqytzQmPZyNSbfqZERjUraK6G9VP%2Bik9BPz6Fb1eoM8At7GwtMAKdN3rF91kM4Ioz0cy7hDvN%2BrjtEtjs94YV%2FqsOXuAkykC57RF%2F0Z%2FfZtzegnT446h5xdjmsJB%2BLIOGCCvZZzfv02PczK0Wn2uSlnOXyOY8PLjhxLX6bkuCPlGY4uL1Dlz3HSlOwj7eE2kcaEzD%2FsWMWGzb%2Fok0HzMK2Q4%2BNzMw3cCNNOotRMqHEl%2B80mQ4RlWuHVM4GnUyceQWhSI0QxlSnPHSnvulKly7NU%2BXNgU%2FGx2f8S2GRpNaxgb4s82Cxmt0FebN7K67dOotRsbJ7FyzhGQR7QnRTiEZoZfskRbGbKc0fKE%2Bf3vNiMyJ8Dm7u9Gd3qXNOkF0Q0L2vEXcxmjryYLXgvR2UE%2B2H5HFRu8CDEKNACVKbF5Hn6CJ3lvMY7d4Q6NcJ5T4PuVNRM6shwlI4MOEPvtJidITmx%2BWXPgz6JEVzonjnAs%2FUQpjiGpXItHqFBH6THQJgdgT82gvuWnPwwj0QogM0oyDJNO5iCpb6tHk0NU1r%2BPw%3D%3D%3C%2Fdiagram%3E%3C%2Fmxfile%3E))
- **Deliverables:**
  - [Business Process Diagram (PDF)](docs/business_process/business_process_diagram.pdf)
  - [Business Process Explanation (PDF)](docs/business_process/business_process_explanation.pdf)
---

## 7. Repository Structure

```text
Ishimwe_kevin_20251SEN190_apiThreatLog/
├── README.md
├── docs/
│   ├── research/
│   │   └── research_log.md
    |___business_process/[cite: 4]
        ├── business_process_diagram.pdf[cite: 4]
        └── business_process_explanation.pdf[cite: 4]
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
