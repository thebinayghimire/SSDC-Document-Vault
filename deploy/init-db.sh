#!/bin/sh
# PostgreSQL invokes this only for a fresh volume; existing hosts require the runbook.
set -eu
export SSDC_RUNTIME_PASSWORD="$(tr -d '\r\n' < /run/secrets/db_password)"
export SSDC_MIGRATION_PASSWORD="$(tr -d '\r\n' < /run/secrets/db_migration_password)"
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv runtime_password SSDC_RUNTIME_PASSWORD
\getenv migration_password SSDC_MIGRATION_PASSWORD
SELECT format('CREATE ROLE ssdc_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'runtime_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ssdc_runtime') \gexec
SELECT format('CREATE ROLE ssdc_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L', :'migration_password')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'ssdc_migrator') \gexec
SELECT format('ALTER ROLE ssdc_runtime PASSWORD %L', :'runtime_password') \gexec
SELECT format('ALTER ROLE ssdc_migrator PASSWORD %L', :'migration_password') \gexec
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM ssdc_runtime;
GRANT USAGE ON SCHEMA public TO ssdc_runtime;
ALTER SCHEMA public OWNER TO ssdc_migrator;
SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database()) \gexec
SELECT format('ALTER DATABASE %I OWNER TO ssdc_migrator', current_database()) \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO ssdc_runtime', current_database()) \gexec
SQL
unset SSDC_RUNTIME_PASSWORD SSDC_MIGRATION_PASSWORD
