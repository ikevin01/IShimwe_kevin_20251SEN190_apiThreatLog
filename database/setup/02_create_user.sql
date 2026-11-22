-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : B 
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 02_create_user.sql (Create PDB Admin User & Grant DBA)
-- ============================================================================

ALTER SESSION SET CONTAINER = b_20251sen190_kevin_api_db;

CREATE USER kevin_admin IDENTIFIED BY kevin;

GRANT DBA TO kevin_admin;
GRANT CONNECT, RESOURCE TO kevin_admin;

-- Verify user creation inside the PDB
SELECT username, account_status, created
FROM dba_users
WHERE username = 'KEVIN_ADMIN';