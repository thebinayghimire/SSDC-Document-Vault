#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

python -m pip install --require-hashes -r requirements.txt
npm ci --ignore-scripts
npm run vendor
python manage.py check
python manage.py collectstatic --no-input
python manage.py migrate --no-input

if [ -n "${DJANGO_SUPERUSER_USERNAME:-}" ] && [ -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]; then
  python manage.py ensure_admin
fi
