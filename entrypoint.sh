#!/bin/sh
# Start PostgreSQL with its data dir on the sealed /data volume, then exec the
# service. /data is the per-app encrypted volume whose key is reconstructed from
# the Enclave Vault constellation at boot — so all user state is encrypted at
# rest under the owner's key, and survives restarts + owner-approved upgrades.
set -e

export PGDATA=/data/pgdata
PGPORT=5432

mkdir -p "$PGDATA"
chown -R postgres:postgres "$PGDATA"
chmod 700 "$PGDATA"

if [ ! -s "$PGDATA/PG_VERSION" ]; then
  echo "initialising PostgreSQL on the sealed /data volume…"
  su postgres -c "initdb -D '$PGDATA' --auth-local=trust --auth-host=reject >/dev/null"
fi

# Postgres listens on localhost only — reachable only from inside this enclave
# container, never exposed to the host or the network. The service connects over
# the local unix socket (auth-local=trust), so no DB password is needed.
su postgres -c "pg_ctl -D '$PGDATA' -o '-c listen_addresses=127.0.0.1 -p $PGPORT' -w start"

if ! su postgres -c "psql -p $PGPORT -tAc \"SELECT 1 FROM pg_database WHERE datname='chat'\"" | grep -q 1; then
  su postgres -c "psql -p $PGPORT -c 'CREATE DATABASE chat'"
fi

export DATABASE_URL="${DATABASE_URL:-postgres://postgres@/chat?host=/var/run/postgresql&sslmode=disable}"

echo "starting chat-service on \$PORT=${PORT:-8080}…"
exec chat-service
