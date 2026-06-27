#!/bin/sh
# Start PostgreSQL with its data dir on the sealed /data volume, then exec the
# service. /data is the per-app encrypted volume whose key is reconstructed from
# the Enclave Vault constellation at boot — so all user state is encrypted at
# rest under the owner's key, and survives restarts + owner-approved upgrades.
#
# Deliberately NOT `set -e`: a Postgres hiccup must not stop the service from
# binding its port. chat-service starts in degraded mode and reports the DB
# state on /healthz, so a failure is visible remotely (containers have no
# stdout capture) instead of crash-looping invisibly.

export PGDATA=/data/pgdata
PGPORT=5432

mkdir -p "$PGDATA" 2>/dev/null || echo "entrypoint: mkdir $PGDATA failed"
chown -R postgres:postgres "$PGDATA" 2>/dev/null || echo "entrypoint: chown $PGDATA failed"
chmod 700 "$PGDATA" 2>/dev/null || true

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "entrypoint: initialising PostgreSQL on /data…"
  # Trust loopback only: Postgres binds 127.0.0.1 (never the host/network), so
  # trusting local TCP + socket is safe and needs no DB password.
  su postgres -c "initdb -D '$PGDATA' --auth-local=trust --auth-host=trust" || echo "entrypoint: initdb failed"
fi

# Postgres listens on loopback only — reachable solely from inside this enclave
# container.
su postgres -c "pg_ctl -D '$PGDATA' -o '-c listen_addresses=127.0.0.1 -p $PGPORT' -w start" || echo "entrypoint: pg_ctl start failed"

if ! su postgres -c "psql -p $PGPORT -tAc \"SELECT 1 FROM pg_database WHERE datname='chat'\"" 2>/dev/null | grep -q 1; then
  su postgres -c "psql -p $PGPORT -c 'CREATE DATABASE chat'" || echo "entrypoint: create database failed"
fi

export DATABASE_URL="${DATABASE_URL:-postgres://postgres@127.0.0.1:5432/chat?sslmode=disable}"

echo "entrypoint: starting chat-service on \$PORT=${PORT:-8080}…"
exec chat-service
