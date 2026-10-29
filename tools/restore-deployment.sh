#!/usr/bin/env bash
set -euo pipefail

bundle=${1:?usage: restore-deployment.sh BUNDLE [TARGET_DIR]}
target=${2:-/opt/cphomework-compute}

umask 077
install -d -m 700 "$target"
tar --numeric-owner --extract --file "$bundle" --directory "$target"
chmod 600 "$target/.env"
chmod 644 "$target/secrets/ssh/known_hosts"
chmod 750 "$target/secrets/ssh"
echo "restored deployment files to $target"
echo "Review .env and host access before: cd $target && docker compose up -d"
