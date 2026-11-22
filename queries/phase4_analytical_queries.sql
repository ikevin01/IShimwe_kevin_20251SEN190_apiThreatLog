-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : phase4_analytical_queries.sql (Joins, GROUP BY, Subqueries & Views)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;
SET LINESIZE 200
SET PAGESIZE 100

-- 1. Multi-Table JOIN: High-risk SQL injection incidents with endpoint details and lexical counts
SELECT st.threat_id, rl.source_ip, ae.http_method, ae.endpoint_path,
       st.risk_score, lm.url_single_q, lm.body_single_q, lm.url_badwords + lm.body_badwords AS badwords
FROM security_threats st
JOIN request_logs rl ON st.log_id = rl.log_id
JOIN api_endpoints ae ON rl.endpoint_id = ae.endpoint_id
JOIN request_lexical_metrics lm ON rl.log_id = lm.log_id
WHERE st.threat_type = 'SQL_INJECTION'
FETCH FIRST 10 ROWS ONLY;

-- 2. GROUP BY Aggregation: Threat distribution and model accuracy by threat category
SELECT threat_type,
       COUNT(*) AS incident_count,
       ROUND(AVG(risk_score), 2) AS avg_risk_score,
       SUM(CASE WHEN actual_class = model_prediction THEN 1 ELSE 0 END) AS model_matches
FROM security_threats
GROUP BY threat_type
ORDER BY incident_count DESC;

-- 3. Correlated Subquery: Endpoints whose average risk score exceeds the overall system average
SELECT ae.endpoint_id, ae.http_method, ae.endpoint_path, ae.sensitivity_level
FROM api_endpoints ae
WHERE EXISTS (
    SELECT 1
    FROM request_logs rl
    JOIN security_threats st ON rl.log_id = st.log_id
    WHERE rl.endpoint_id = ae.endpoint_id
      AND st.risk_score > (SELECT AVG(risk_score) FROM security_threats)
)
FETCH FIRST 10 ROWS ONLY;

-- 4. Querying All Three Views (Reporting, Summary, and Read-Only Protected View)
SELECT * FROM vw_threat_incident_report FETCH FIRST 10 ROWS ONLY;
SELECT * FROM vw_endpoint_threat_summary FETCH FIRST 10 ROWS ONLY;
SELECT * FROM vw_readonly_critical_threats FETCH FIRST 10 ROWS ONLY;

-- 5. Demonstrate WITH READ ONLY protection on VW_READONLY_CRITICAL_THREATS (ORA-42399)
DELETE FROM vw_readonly_critical_threats WHERE ROWNUM = 1;
