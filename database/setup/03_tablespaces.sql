-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 03_tablespaces.sql (Create Data, Index & Temp Tablespaces)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

-- 1. Data tablespace: 100M, AUTOEXTEND ON NEXT 10M MAXSIZE 1G
CREATE TABLESPACE apithreat_data
  DATAFILE '/opt/oracle/oradata/FREE/b_20251sen190_kevin_api_db/apithreat_data01.dbf'
  SIZE 100M
  AUTOEXTEND ON NEXT 10M MAXSIZE 1G;

-- 2. Index tablespace: 50M, AUTOEXTEND ON NEXT 10M MAXSIZE 500M
CREATE TABLESPACE apithreat_idx
  DATAFILE '/opt/oracle/oradata/FREE/b_20251sen190_kevin_api_db/apithreat_idx01.dbf'
  SIZE 50M
  AUTOEXTEND ON NEXT 10M MAXSIZE 500M;

-- 3. Temporary tablespace: 50M, AUTOEXTEND ON NEXT 10M MAXSIZE 500M
CREATE TEMPORARY TABLESPACE apithreat_temp
  TEMPFILE '/opt/oracle/oradata/FREE/b_20251sen190_kevin_api_db/apithreat_temp01.dbf'
  SIZE 50M
  AUTOEXTEND ON NEXT 10M MAXSIZE 500M;

-- Assign default/temp tablespaces and unlimited quotas to kevin_admin
ALTER USER kevin_admin
  DEFAULT TABLESPACE apithreat_data
  TEMPORARY TABLESPACE apithreat_temp
  QUOTA UNLIMITED ON apithreat_data
  QUOTA UNLIMITED ON apithreat_idx;