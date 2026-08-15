#!/bin/sh
set -eu
mkdir -p /models /var/lib/celery
chown -R nobody:nogroup /models /var/lib/celery
if [ "${RUN_MIGRATIONS:-0}" = "1" ]; then
  echo "Applying database migrations..."
  alembic upgrade head
fi
if [ "$(id -u)" = "0" ]; then
  exec setpriv --reuid=nobody --regid=nogroup --init-groups --no-new-privs "$@"
fi
exec "$@"
