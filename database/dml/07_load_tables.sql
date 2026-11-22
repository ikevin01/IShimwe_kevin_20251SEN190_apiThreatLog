-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 07_load_tables.sql (Populate 3NF Tables: Parent -> Child)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

INSERT INTO api_endpoints (http_method, endpoint_path, path_length, sensitivity_level)
SELECT http_method,
       endpoint_path,
       MAX(path_length),
       CASE
         WHEN LOWER(endpoint_path) LIKE '%login%' OR LOWER(endpoint_path) LIKE '%admin%' THEN 'CRITICAL'
         WHEN LOWER(endpoint_path) LIKE '%bank%' OR LOWER(endpoint_path) LIKE '%user_redacted%' THEN 'HIGH'
         WHEN endpoint_path = '/unknown' THEN 'LOW'
         ELSE 'MEDIUM'
       END AS sensitivity_level
FROM stg_web_traffic_clean
GROUP BY http_method, endpoint_path;

INSERT INTO request_logs (log_id, endpoint_id, source_ip, body_length, http_status, logged_at)
SELECT c.clean_id,
       ae.endpoint_id,
       '192.168.' || MOD(c.clean_id, 250) || '.' || (MOD(c.clean_id * 7, 250) + 1) AS source_ip,
       c.body_length,
       CASE WHEN c.actual_class = 1 OR c.model_prediction = 1 THEN 403 ELSE 200 END AS http_status,
       SYSTIMESTAMP - NUMTODSINTERVAL((300 - c.clean_id) * 15, 'SECOND') AS logged_at
FROM stg_web_traffic_clean c
JOIN api_endpoints ae
  ON c.http_method = ae.http_method
 AND c.endpoint_path = ae.endpoint_path;

INSERT INTO request_lexical_metrics (
    log_id, url_single_q, url_double_q, url_dashes, url_braces, url_spaces,
    url_percentages, url_semicolons, url_angle_brackets, url_special_chars, url_badwords,
    body_single_q, body_double_q, body_dashes, body_braces, body_spaces,
    body_percentages, body_semicolons, body_angle_brackets, body_special_chars, body_badwords
)
SELECT clean_id,
       url_single_q, url_double_q, url_dashes, url_braces, url_spaces,
       url_percentages, url_semicolons, url_angle_brackets, url_special_chars, url_badwords,
       body_single_q, body_double_q, body_dashes, body_braces, body_spaces,
       body_percentages, body_semicolons, body_angle_brackets, body_special_chars, body_badwords
FROM stg_web_traffic_clean;

INSERT INTO security_threats (log_id, threat_type, actual_class, model_prediction, risk_score, detected_at)
SELECT c.clean_id,
       CASE
         WHEN (c.url_badwords + c.body_badwords + c.url_single_q + c.body_single_q) > 0 THEN 'SQL_INJECTION'
         WHEN (c.url_angle_brackets + c.body_angle_brackets) > 0 THEN 'XSS_PROBE'
         WHEN LOWER(c.endpoint_path) LIKE '%admin%' OR LOWER(c.endpoint_path) LIKE '%.xls%' THEN 'SENSITIVE_FILE_ACCESS'
         ELSE 'ANOMALOUS_PAYLOAD'
       END AS threat_type,
       c.actual_class,
       c.model_prediction,
       LEAST(100, (c.actual_class * 45) + (c.model_prediction * 35)
                + ((c.url_badwords + c.body_badwords) * 10)
                + LEAST(15, c.url_special_chars + c.body_special_chars)) AS risk_score,
       rl.logged_at
FROM stg_web_traffic_clean c
JOIN request_logs rl ON c.clean_id = rl.log_id
WHERE c.actual_class = 1 OR c.model_prediction = 1;

INSERT INTO ip_quarantine_list (threat_id, blocked_ip, block_reason, is_active, quarantined_at, expires_at)
SELECT MIN(st.threat_id),
       rl.source_ip,
       'Automated block: risk score ' || MAX(st.risk_score) || ' (' || MAX(st.threat_type) || ')',
       'Y',
       MAX(st.detected_at),
       MAX(st.detected_at) + INTERVAL '24' HOUR
FROM security_threats st
JOIN request_logs rl ON st.log_id = rl.log_id
WHERE st.risk_score >= 80
GROUP BY rl.source_ip;

COMMIT;

SELECT 'STG_WEB_TRAFFIC_RAW'     AS table_name, COUNT(*) AS row_count FROM stg_web_traffic_raw UNION ALL
SELECT 'STG_WEB_TRAFFIC_CLEAN'   AS table_name, COUNT(*) AS row_count FROM stg_web_traffic_clean UNION ALL
SELECT 'API_ENDPOINTS'           AS table_name, COUNT(*) AS row_count FROM api_endpoints UNION ALL
SELECT 'REQUEST_LOGS'            AS table_name, COUNT(*) AS row_count FROM request_logs UNION ALL
SELECT 'REQUEST_LEXICAL_METRICS' AS table_name, COUNT(*) AS row_count FROM request_lexical_metrics UNION ALL
SELECT 'SECURITY_THREATS'        AS table_name, COUNT(*) AS row_count FROM security_threats UNION ALL
SELECT 'IP_QUARANTINE_LIST'      AS table_name, COUNT(*) AS row_count FROM ip_quarantine_list;
