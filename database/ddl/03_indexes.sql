-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 03_indexes.sql (FK, Composite & Function-Based Indexes)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

-- 1. Foreign Key Index on REQUEST_LOGS(endpoint_id)
-- Justification: Speeds up joins with API_ENDPOINTS and prevents full table locks on parent deletes.
CREATE INDEX idx_request_logs_endpoint_id
  ON request_logs (endpoint_id)
  TABLESPACE apithreat_idx;

-- 2. Foreign Key Index on IP_QUARANTINE_LIST(threat_id)
-- Justification: Accelerates joins and ON DELETE SET NULL lookups when a parent threat is deleted.
CREATE INDEX idx_ip_quarantine_threat_id
  ON ip_quarantine_list (threat_id)
  TABLESPACE apithreat_idx;

-- 3. Composite Index on REQUEST_LOGS(source_ip, logged_at)
-- Justification: Optimizes time-window rate-limiting and IP traffic history queries in WHERE/ORDER BY.
CREATE INDEX idx_request_logs_ip_time
  ON request_logs (source_ip, logged_at)
  TABLESPACE apithreat_idx;

-- 4. Composite Index on SECURITY_THREATS(threat_type, risk_score)
-- Justification: Accelerates SOC dashboard filtering by attack category and high-risk severity sorting.
CREATE INDEX idx_security_threats_type_score
  ON security_threats (threat_type, risk_score)
  TABLESPACE apithreat_idx;

-- 5. Function-Based Index on API_ENDPOINTS(UPPER(endpoint_path))
-- Justification: Enables fast case-insensitive URI path lookups during threat detection.
CREATE INDEX idx_api_endpoints_upper_path
  ON api_endpoints (UPPER(endpoint_path))
  TABLESPACE apithreat_idx;

-- Verify all indexes reside in APITHREAT_IDX
SELECT index_name, table_name, uniqueness, tablespace_name, status
FROM user_indexes
WHERE table_name IN ('API_ENDPOINTS', 'REQUEST_LOGS', 'REQUEST_LEXICAL_METRICS',
                     'SECURITY_THREATS', 'IP_QUARANTINE_LIST')
ORDER BY table_name, index_name;
