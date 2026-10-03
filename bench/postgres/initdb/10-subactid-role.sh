#!/usr/bin/env bash
# Creates an ordinary login role for the control plane, which must not connect as a superuser.
# A superuser bypasses the REVOKE that guards audit_events. The password comes from rig.sh.

set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<-SQL
	CREATE ROLE subactid LOGIN PASSWORD '${SUBACTID_DB_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
	ALTER DATABASE subactid OWNER TO subactid;
SQL

# Owns the schema so `migrate` can create the ledger and its partitions. This is the default
# single-role layout.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname subactid <<-SQL
	ALTER SCHEMA public OWNER TO subactid;
	GRANT ALL ON SCHEMA public TO subactid;
SQL

# Installing an extension needs a superuser. pg_stat_statements is used by statements.sh.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname subactid <<-SQL
	CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
SQL
