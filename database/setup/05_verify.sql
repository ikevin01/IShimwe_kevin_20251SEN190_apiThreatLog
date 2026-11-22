-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 05_verify.sql (Phase III Verification Queries)
-- ============================================================================

SET LINESIZE 200
SET PAGESIZE 100
COLUMN pdb_name FORMAT A32
COLUMN username FORMAT A15
COLUMN default_tablespace FORMAT A18
COLUMN temporary_tablespace FORMAT A18
COLUMN tablespace_name FORMAT A18
COLUMN file_name FORMAT A75

-- 1. Confirm PDB exists and is OPEN
SELECT name AS pdb_name, open_mode, restricted, open_time
FROM v$pdbs
WHERE name = UPPER('b_20251sen190_kevin_api_db');

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

-- 2. Confirm admin user's default and temporary tablespaces + quotas
SELECT username, default_tablespace, temporary_tablespace, account_status
FROM dba_users
WHERE username = 'KEVIN_ADMIN';

SELECT username, tablespace_name, max_bytes
FROM dba_ts_quotas
WHERE username = 'KEVIN_ADMIN';

-- 3. Confirm each tablespace with size, autoextend setting, and max size
SELECT tablespace_name,
       ROUND(bytes / 1024 / 1024, 2) AS size_mb,
       autoextensible,
       ROUND(maxbytes / 1024 / 1024, 2) AS max_size_mb,
       file_name
FROM dba_data_files
WHERE tablespace_name IN ('APITHREAT_DATA', 'APITHREAT_IDX')
UNION ALL
SELECT tablespace_name,
       ROUND(bytes / 1024 / 1024, 2) AS size_mb,
       autoextensible,
       ROUND(maxbytes / 1024 / 1024, 2) AS max_size_mb,
       file_name
FROM dba_temp_files
WHERE tablespace_name = 'APITHREAT_TEMP';

-- 4. Confirm archive log mode of the database
ALTER SESSION SET CONTAINER = CDB$ROOT;
SELECT name AS cdb_name, log_mode, TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI:SS') AS verified_at
FROM v$database;