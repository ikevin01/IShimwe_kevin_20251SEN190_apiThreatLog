-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 10_validation.sql (Row Count Reconciliation, Orphan Checks & Execution Plan)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;
SET LINESIZE 200
SET PAGESIZE 100

-- 1. Staging vs Production Table Row Count Reconciliation
SELECT 'STG_WEB_TRAFFIC_RAW (All CSV rows)'       AS layer, COUNT(*) AS row_count FROM stg_web_traffic_raw UNION ALL
SELECT 'STG_WEB_TRAFFIC_CLEAN (Deduplicated)'     AS layer, COUNT(*) AS row_count FROM stg_web_traffic_clean UNION ALL
SELECT 'API_ENDPOINTS (Unique Method+Path)'       AS layer, COUNT(*) AS row_count FROM api_endpoints UNION ALL
SELECT 'REQUEST_LOGS (1 per clean traffic event)' AS layer, COUNT(*) AS row_count FROM request_logs UNION ALL
SELECT 'REQUEST_LEXICAL_METRICS (1:1 with logs)'  AS layer, COUNT(*) AS row_count FROM request_lexical_metrics UNION ALL
SELECT 'SECURITY_THREATS (Flagged anomalies)'     AS layer, COUNT(*) AS row_count FROM security_threats UNION ALL
SELECT 'IP_QUARANTINE_LIST (High-risk IP bans)'   AS layer, COUNT(*) AS row_count FROM ip_quarantine_list;

-- 2. Orphan Foreign Key Verification (All counts must be 0)
SELECT 'Orphan REQUEST_LOGS without API_ENDPOINTS'      AS check_name, COUNT(*) AS orphan_count
FROM request_logs rl LEFT JOIN api_endpoints ae ON rl.endpoint_id = ae.endpoint_id WHERE ae.endpoint_id IS NULL
UNION ALL
SELECT 'Orphan LEXICAL_METRICS without REQUEST_LOGS'    AS check_name, COUNT(*) AS orphan_count
FROM request_lexical_metrics lm LEFT JOIN request_logs rl ON lm.log_id = rl.log_id WHERE rl.log_id IS NULL
UNION ALL
SELECT 'Orphan SECURITY_THREATS without REQUEST_LOGS'   AS check_name, COUNT(*) AS orphan_count
FROM security_threats st LEFT JOIN request_logs rl ON st.log_id = rl.log_id WHERE rl.log_id IS NULL
UNION ALL
SELECT 'Orphan IP_QUARANTINE without SECURITY_THREATS'  AS check_name, COUNT(*) AS orphan_count
FROM ip_quarantine_list iq LEFT JOIN security_threats st ON iq.threat_id = st.threat_id
WHERE iq.threat_id IS NOT NULL AND st.threat_id IS NULL;

-- 3. Confirm all constraints remain ENABLED and VALIDATED
SELECT status, validated, COUNT(*) AS total_constraints
FROM user_constraints
WHERE table_name IN ('API_ENDPOINTS', 'REQUEST_LOGS', 'REQUEST_LEXICAL_METRICS',
                     'SECURITY_THREATS', 'IP_QUARANTINE_LIST')
GROUP BY status, validated;

-- 4. Execution Plan Comparison (Before vs After Composite Index IDX_SECURITY_THREATS_TYPE_SCORE)
DROP INDEX idx_security_threats_type_score;

EXPLAIN PLAN FOR
SELECT threat_id, log_id, risk_score
FROM security_threats
WHERE threat_type = 'SQL_INJECTION' AND risk_score >= 85;

SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY);

CREATE INDEX idx_security_threats_type_score
  ON security_threats (threat_type, risk_score)
  TABLESPACE apithreat_idx;

EXPLAIN PLAN FOR
SELECT threat_id, log_id, risk_score
FROM security_threats
WHERE threat_type = 'SQL_INJECTION' AND risk_score >= 85;

SELECT * FROM TABLE(DBMS_XPLAN.DISPLAY);
