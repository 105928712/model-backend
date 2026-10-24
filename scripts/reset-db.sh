#!/usr/bin/env bash
# Delete the Postgres container and its volume, so every account and check is gone
cd "$(dirname "${BASH_SOURCE[0]}")/.."
docker compose down --volumes && echo "Database container and volume deleted"
