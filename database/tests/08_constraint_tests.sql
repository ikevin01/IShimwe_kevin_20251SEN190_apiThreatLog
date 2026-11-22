-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 08_constraint_tests.sql (Constraint Violation & Status Tests)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;
SET SERVEROUTPUT ON

-- 1. Verify all constraints are ENABLED and VALIDATED (0 SYS_C% names)
SELECT constraint_name, constraint_type, table_name, status, validated
FROM user_constraints
WHERE table_name IN ('API_ENDPOINTS', 'REQUEST_LOGS', 'REQUEST_LEXICAL_METRICS',
                     'SECURITY_THREATS', 'IP_QUARANTINE_LIST')
ORDER BY table_name, constraint_type, constraint_name;

-- 2. Negative Test A: PRIMARY KEY violation (ORA-00001)
INSERT INTO api_endpoints (endpoint_id, http_method, endpoint_path)
VALUES (1, 'GET', '/duplicate-pk-test');

-- 3. Negative Test B: FOREIGN KEY violation (ORA-02291)
INSERT INTO request_logs (endpoint_id, source_ip, body_length, http_status)
VALUES (999999, '10.0.0.99', 120, 200);

-- 4. Negative Test C: NOT NULL violation (ORA-01400)
INSERT INTO api_endpoints (http_method, endpoint_path)
VALUES ('GET', NULL);

-- 5. Negative Test D: UNIQUE violation (ORA-00001)
INSERT INTO ip_quarantine_list (blocked_ip, block_reason)
SELECT blocked_ip, 'Duplicate IP test'
FROM ip_quarantine_list
WHERE ROWNUM = 1;

-- 6. Negative Test E: CHECK constraint violation (ORA-02290)
INSERT INTO security_threats (log_id, threat_type, actual_class, model_prediction, risk_score)
VALUES (1, 'SQL_INJECTION', 1, 1, 150);
