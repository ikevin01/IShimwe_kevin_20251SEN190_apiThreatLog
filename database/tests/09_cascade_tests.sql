-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 09_cascade_tests.sql (Referential Action Tests: NO ACTION, CASCADE, SET NULL)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;
SET SERVEROUTPUT ON

-- 1. Demonstrate NO ACTION (ORA-02292): Deleting a parent API_ENDPOINTS row with child logs fails
DELETE FROM api_endpoints WHERE endpoint_id = 1;

-- 2. Demonstrate ON DELETE SET NULL:
-- Deleting a parent SECURITY_THREATS row sets IP_QUARANTINE_LIST.threat_id to NULL while keeping the IP ban
SAVEPOINT sp_before_set_null;

SELECT quarantine_id, threat_id, blocked_ip, is_active
FROM ip_quarantine_list
WHERE threat_id IS NOT NULL AND ROWNUM = 1;

DELETE FROM security_threats
WHERE threat_id = (SELECT threat_id FROM ip_quarantine_list WHERE threat_id IS NOT NULL AND ROWNUM = 1);

SELECT quarantine_id, threat_id, blocked_ip, is_active
FROM ip_quarantine_list
WHERE threat_id IS NULL;

ROLLBACK TO sp_before_set_null;

-- 3. Demonstrate ON DELETE CASCADE:
-- Deleting a parent REQUEST_LOGS row automatically deletes its child REQUEST_LEXICAL_METRICS and SECURITY_THREATS rows
SAVEPOINT sp_before_cascade;

SELECT (SELECT COUNT(*) FROM request_logs WHERE log_id = 1) AS parent_logs,
       (SELECT COUNT(*) FROM request_lexical_metrics WHERE log_id = 1) AS child_metrics,
       (SELECT COUNT(*) FROM security_threats WHERE log_id = 1) AS child_threats
FROM dual;

DELETE FROM request_logs WHERE log_id = 1;

SELECT (SELECT COUNT(*) FROM request_logs WHERE log_id = 1) AS parent_logs_after,
       (SELECT COUNT(*) FROM request_lexical_metrics WHERE log_id = 1) AS child_metrics_after,
       (SELECT COUNT(*) FROM security_threats WHERE log_id = 1) AS child_threats_after
FROM dual;

ROLLBACK TO sp_before_cascade;
