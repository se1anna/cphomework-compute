#!/usr/bin/env bash
set -euo pipefail

output=${1:-cphomework-compute-deployment.tar}
base_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

if [[ ! -r "$base_dir/secrets/ssh/known_hosts" || ! -r "$base_dir/.env" ]]; then
  echo "missing .env or secrets/ssh/known_hosts" >&2
  exit 1
fi

umask 077
tar --numeric-owner --xattrs --acls -cf "$output" \
  -C "$base_dir" docker-compose.yml .env secrets/ssh/known_hosts
chmod 600 "$output"
echo "created $output"
echo "This bundle contains .env and Git host keys; review .env before deployment. Task deploy keys are supplied per task and are not bundled."
