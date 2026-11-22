-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 04_views.sql (Reporting, Summary & Protected Views)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

-- 1. Reporting View: Joins 4 tables into a single readable SOC alert feed
CREATE OR REPLACE VIEW vw_threat_incident_report AS
SELECT st.threat_id,
       rl.log_id,
       rl.logged_at,
       rl.source_ip,
       ae.http_method,
       ae.endpoint_path,
       ae.sensitivity_level,
       st.threat_type,
       st.risk_score,
       lm.url_badwords + lm.body_badwords AS total_sqli_keywords,
       NVL(iq.is_active, 'N') AS ip_quarantined
FROM security_threats st
JOIN request_logs rl ON st.log_id = rl.log_id
JOIN api_endpoints ae ON rl.endpoint_id = ae.endpoint_id
JOIN request_lexical_metrics lm ON rl.log_id = lm.log_id
LEFT JOIN ip_quarantine_list iq ON st.threat_id = iq.threat_id;

-- 2. Summary View: Aggregates request volume, threats, and average risk per endpoint
CREATE OR REPLACE VIEW vw_endpoint_threat_summary AS
SELECT ae.endpoint_id,
       ae.http_method,
       ae.endpoint_path,
       ae.sensitivity_level,
       COUNT(rl.log_id) AS total_requests,
       COUNT(st.threat_id) AS total_threats,
       ROUND(NVL(AVG(st.risk_score), 0), 2) AS avg_risk_score,
       MAX(rl.body_length) AS max_payload_bytes
FROM api_endpoints ae
LEFT JOIN request_logs rl ON ae.endpoint_id = rl.endpoint_id
LEFT JOIN security_threats st ON rl.log_id = st.log_id
GROUP BY ae.endpoint_id, ae.http_method, ae.endpoint_path, ae.sensitivity_level;

-- 3. Protected View (WITH READ ONLY): Immutable audit feed for external security auditors
-- Justification: WITH READ ONLY prevents any DML (INSERT/UPDATE/DELETE) through the view,
-- preserving forensic audit integrity of confirmed high-risk threats.
CREATE OR REPLACE VIEW vw_readonly_critical_threats AS
SELECT threat_id, log_id, threat_type, actual_class, model_prediction, risk_score, detected_at
FROM security_threats
WHERE risk_score >= 70
WITH READ ONLY;
