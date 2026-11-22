-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : Group B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 02_constraints.sql (Named PK, FK, UQ, CK Constraints)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

-- 1. API_ENDPOINTS Constraints
ALTER TABLE api_endpoints
  ADD CONSTRAINT pk_api_endpoints PRIMARY KEY (endpoint_id)
  USING INDEX TABLESPACE apithreat_idx;

ALTER TABLE api_endpoints
  ADD CONSTRAINT uq_api_endpoints_method_path UNIQUE (http_method, endpoint_path)
  USING INDEX TABLESPACE apithreat_idx;

ALTER TABLE api_endpoints
  ADD CONSTRAINT ck_api_endpoints_method
  CHECK (http_method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'UNKNOWN'));

ALTER TABLE api_endpoints
  ADD CONSTRAINT ck_api_endpoints_path_len CHECK (path_length >= 0);

ALTER TABLE api_endpoints
  ADD CONSTRAINT ck_api_endpoints_sensitivity
  CHECK (sensitivity_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'));

-- 2. REQUEST_LOGS Constraints
ALTER TABLE request_logs
  ADD CONSTRAINT pk_request_logs PRIMARY KEY (log_id)
  USING INDEX TABLESPACE apithreat_idx;

-- NO ACTION (Oracle default): Prevent deleting an endpoint that has audit logs
ALTER TABLE request_logs
  ADD CONSTRAINT fk_request_logs_endpoints
  FOREIGN KEY (endpoint_id) REFERENCES api_endpoints (endpoint_id);

ALTER TABLE request_logs
  ADD CONSTRAINT ck_request_logs_body_len CHECK (body_length >= 0);

ALTER TABLE request_logs
  ADD CONSTRAINT ck_request_logs_status CHECK (http_status BETWEEN 100 AND 599);

-- 3. REQUEST_LEXICAL_METRICS Constraints
ALTER TABLE request_lexical_metrics
  ADD CONSTRAINT pk_request_lexical_metrics PRIMARY KEY (metric_id)
  USING INDEX TABLESPACE apithreat_idx;

ALTER TABLE request_lexical_metrics
  ADD CONSTRAINT uq_request_lexical_metrics_log UNIQUE (log_id)
  USING INDEX TABLESPACE apithreat_idx;

-- ON DELETE CASCADE: Lexical counts cannot exist without their parent request log
ALTER TABLE request_lexical_metrics
  ADD CONSTRAINT fk_lexical_metrics_logs
  FOREIGN KEY (log_id) REFERENCES request_logs (log_id) ON DELETE CASCADE;

ALTER TABLE request_lexical_metrics
  ADD CONSTRAINT ck_lexical_metrics_counts
  CHECK (url_single_q >= 0 AND url_double_q >= 0 AND url_dashes >= 0
     AND url_braces >= 0 AND url_spaces >= 0 AND url_percentages >= 0
     AND url_semicolons >= 0 AND url_angle_brackets >= 0
     AND url_special_chars >= 0 AND url_badwords >= 0
     AND body_single_q >= 0 AND body_double_q >= 0 AND body_dashes >= 0
     AND body_braces >= 0 AND body_spaces >= 0 AND body_percentages >= 0
     AND body_semicolons >= 0 AND body_angle_brackets >= 0
     AND body_special_chars >= 0 AND body_badwords >= 0);

-- 4. SECURITY_THREATS Constraints
ALTER TABLE security_threats
  ADD CONSTRAINT pk_security_threats PRIMARY KEY (threat_id)
  USING INDEX TABLESPACE apithreat_idx;

ALTER TABLE security_threats
  ADD CONSTRAINT uq_security_threats_log UNIQUE (log_id)
  USING INDEX TABLESPACE apithreat_idx;

-- ON DELETE CASCADE: Threat alert cannot exist if parent request log is purged
ALTER TABLE security_threats
  ADD CONSTRAINT fk_security_threats_logs
  FOREIGN KEY (log_id) REFERENCES request_logs (log_id) ON DELETE CASCADE;

ALTER TABLE security_threats
  ADD CONSTRAINT ck_security_threats_class CHECK (actual_class IN (0, 1));

ALTER TABLE security_threats
  ADD CONSTRAINT ck_security_threats_pred CHECK (model_prediction IN (0, 1));

ALTER TABLE security_threats
  ADD CONSTRAINT ck_security_threats_score CHECK (risk_score BETWEEN 0 AND 100);

-- 5. IP_QUARANTINE_LIST Constraints
ALTER TABLE ip_quarantine_list
  ADD CONSTRAINT pk_ip_quarantine_list PRIMARY KEY (quarantine_id)
  USING INDEX TABLESPACE apithreat_idx;

ALTER TABLE ip_quarantine_list
  ADD CONSTRAINT uq_ip_quarantine_list_ip UNIQUE (blocked_ip)
  USING INDEX TABLESPACE apithreat_idx;

-- ON DELETE SET NULL: Keep active IP ban even if the triggering threat row is archived
ALTER TABLE ip_quarantine_list
  ADD CONSTRAINT fk_quarantine_threats
  FOREIGN KEY (threat_id) REFERENCES security_threats (threat_id) ON DELETE SET NULL;

ALTER TABLE ip_quarantine_list
  ADD CONSTRAINT ck_ip_quarantine_active CHECK (is_active IN ('Y', 'N'));

-- Verify all named constraints are ENABLED and VALIDATED
SELECT constraint_name, constraint_type, table_name, status, validated
FROM user_constraints
WHERE table_name IN ('API_ENDPOINTS', 'REQUEST_LOGS', 'REQUEST_LEXICAL_METRICS',
                     'SECURITY_THREATS', 'IP_QUARANTINE_LIST')
ORDER BY table_name, constraint_type, constraint_name;
