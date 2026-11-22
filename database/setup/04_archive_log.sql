-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 04_archive_log.sql (Configure CDB Archive Logging & Port)
-- ============================================================================

-- EXPLANATION (CDB vs PDB Scope for Archive Logging):
-- Archive logging cannot be enabled for a single PDB because all Pluggable
-- Databases within a Container Database (CDB) share a single set of online redo
-- log files and a single redo thread managed at the CDB$ROOT instance level.
-- Therefore, switching to ARCHIVELOG mode is a CDB-wide operation requiring
-- SYSDBA privileges and a full CDB mount/restart.

ALTER SESSION SET CONTAINER = CDB$ROOT;

-- 1. Check current archive log mode
ARCHIVE LOG LIST;
SELECT name, log_mode FROM v$database;

-- 2. Steps to enable ARCHIVELOG mode on local Docker installation (SYSDBA):
SHUTDOWN IMMEDIATE;
STARTUP MOUNT;
ALTER DATABASE ARCHIVELOG;
ALTER DATABASE OPEN;
ALTER PLUGGABLE DATABASE b_20251sen190_kevin_api_db OPEN READ WRITE;

-- 3. Verify ARCHIVELOG mode is now active
ARCHIVE LOG LIST;

-- 4. Configure HTTPS port 5590 (last two digits of 20251SEN190 = 90)
ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;
EXEC DBMS_XDB_CONFIG.SETHTTPSPORT(5590);