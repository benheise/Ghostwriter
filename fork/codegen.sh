#!/usr/bin/env bash
# Regenerate javascript/src/__generated__ from this checkout's database schema and Hasura metadata.
#
# Usage: fork/codegen.sh
#
# Starts a throwaway Postgres, applies this checkout's migrations with the upstream Django image, starts
# the upstream Hasura image with this checkout's metadata, checks the metadata is consistent, then runs
# GraphQL codegen, the TypeScript check, and the collaboration GraphQL authorization test in javascript/. Image tags follow VERSION unless
# GW_TEST_IMAGE_TAG is set. Needs Docker, Node and npm.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
tag="${GW_TEST_IMAGE_TAG:-$(head -n1 "$root/VERSION" | tr -d '[:space:]')}"
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
registry="ghcr.io/ghostmanager"
id="gw-fork-codegen-$$"
random() { od -An -N16 -tx1 /dev/urandom | tr -d ' \n'; }
password="$(random)"
admin_secret="$(random)"
action_secret="$(random)"
database_url="postgres://postgres:$password@postgres:5432/ghostwriter"

cleanup() {
    docker rm -f "$id-postgres" "$id-hasura" >/dev/null 2>&1 || true
    docker network rm "$id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$id" >/dev/null
docker run -d --name "$id-postgres" --network "$id" --network-alias postgres \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=ghostwriter \
    "$registry/ghostwriter_postgres:$tag" >/dev/null
for _ in $(seq 1 60); do
    docker exec "$id-postgres" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
done

echo "Applying migrations"
docker run --rm --network "$id" -u "$(id -u):$(id -g)" -e HOME=/tmp \
    -e DJANGO_SETTINGS_MODULE=config.settings.test -e USE_DOCKER=yes \
    -e DATABASE_URL="$database_url" -e HASURA_ACTION_SECRET="$action_secret" \
    -v "$root":/app -w /app --entrypoint python \
    "$registry/ghostwriter_django:$tag" manage.py migrate --noinput >/dev/null

echo "Starting Hasura with this checkout's metadata"
docker run -d --name "$id-hasura" --network "$id" \
    -e HASURA_GRAPHQL_DATABASE_URL="$database_url" \
    -e HASURA_GRAPHQL_ADMIN_SECRET="$admin_secret" \
    -e HASURA_GRAPHQL_METADATA_DIR=/metadata \
    -e HASURA_GRAPHQL_MIGRATIONS_DIR=/migrations \
    -e HASURA_GRAPHQL_ENABLE_TELEMETRY=false \
    -e HASURA_GRAPHQL_ENABLE_CONSOLE=false \
    -e HASURA_ACTION_SECRET="$action_secret" \
    -e ACTIONS_URL_BASE=http://django:8000/api \
    -e HASURA_GRAPHQL_AUTH_HOOK=http://django:8000/api/webhook \
    -v "$root/hasura-docker/metadata":/metadata:ro \
    "$registry/ghostwriter_hasura:$tag" >/dev/null

address=""
for _ in $(seq 1 90); do
    address="$(docker inspect "$id-hasura" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')"
    if [ -n "$address" ] && curl -sf --noproxy '*' -m 2 "http://$address:8080/healthz" >/dev/null 2>&1; then
        break
    fi
    if [ "$(docker inspect "$id-hasura" --format '{{.State.Running}}')" != true ]; then
        docker logs "$id-hasura" 2>&1 | tail -20 >&2
        echo "Hasura stopped; the metadata likely failed to apply" >&2
        exit 1
    fi
    sleep 2
done

inconsistent="$(curl -s --noproxy '*' -m 10 -H "x-hasura-admin-secret: $admin_secret" \
    -d '{"type":"get_inconsistent_metadata","args":{}}' "http://$address:8080/v1/metadata")"
if ! printf '%s' "$inconsistent" | grep -q '"is_consistent":true'; then
    echo "Hasura reports inconsistent metadata: $inconsistent" >&2
    exit 1
fi

echo "Running codegen and the TypeScript check"
cd "$root/javascript"
[ -d node_modules ] || npm ci --no-audit --no-fund
NO_PROXY="$address,${NO_PROXY:-}" no_proxy="$address,${no_proxy:-}" \
    HASURA_GRAPHQL_SERVER_HOSTNAME="$address" HASURA_GRAPHQL_ADMIN_SECRET="$admin_secret" \
    npx graphql-codegen
npm run check
npm run test:collab-graphql-auth
git -C "$root" status --short -- javascript/src/__generated__
