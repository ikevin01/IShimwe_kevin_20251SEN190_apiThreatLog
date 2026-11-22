-- ============================================================================
-- Student Name : Ishimwe Kevin
-- Student ID   : 20251SEN190
-- Group        : B
-- Project Name : API Threat Detection & Security Anomaly Logging Engine
-- Script       : 01_create_pdb.sql (Create & Open Pluggable Database)
-- ============================================================================

ALTER SESSION SET CONTAINER = CDB$ROOT;

-- Create PDB (<= 30 characters: b_20251sen190_kevin_api_db)
CREATE PLUGGABLE DATABASE b_20251sen190_kevin_api_db
  ADMIN USER pdb_seed_admin IDENTIFIED BY kevin
  ROLES = (DBA)
  FILE_NAME_CONVERT = ('/opt/oracle/oradata/FREE/pdbseed/',
                       '/opt/oracle/oradata/FREE/b_20251sen190_kevin_api_db/');

-- Open the PDB and save its state so it auto-opens on CDB restart
ALTER PLUGGABLE DATABASE b_20251sen190_kevin_api_db OPEN READ WRITE;
ALTER PLUGGABLE DATABASE b_20251sen190_kevin_api_db SAVE STATE;

-- Confirm PDB status
SELECT name, open_mode FROM v$pdbs WHERE name = UPPER('b_20251sen190_kevin_api_db');