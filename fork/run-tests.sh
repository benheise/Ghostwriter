#!/usr/bin/env bash
# Run Ghostwriter's Django test suite against this checkout with the environment upstream CI uses (ci.yml).
#
# Usage: fork/run-tests.sh [test labels...]
#
# Starts throwaway Postgres and Redis containers from the upstream images for the version in VERSION,
# then runs `manage.py test --exclude-tag=GitHub` in the upstream Django image of the same version with
# this checkout mounted over its code. The production image lacks the test-only packages, so the
# script downloads factory-boy (at the version in requirements/local.txt) and its dependencies once,
# with the host's pip, into a cache that the container installs from offline. With no labels, it
# first checks that no model change lacks a migration. Set GW_TEST_IMAGE_TAG to use other image tags.
# Containers are removed afterwards. Needs Docker and python3 with pip.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
tag="${GW_TEST_IMAGE_TAG:-$(head -n1 "$root/VERSION" | tr -d '[:space:]')}"
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
registry="ghcr.io/ghostmanager"
id="gw-fork-test-$$"
password="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"

cleanup() {
    docker rm -f "$id-postgres" "$id-redis" >/dev/null 2>&1 || true
    docker network rm "$id" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker network create "$id" >/dev/null
docker run -d --name "$id-postgres" --network "$id" --network-alias postgres \
    -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$password" -e POSTGRES_DB=ghostwriter \
    "$registry/ghostwriter_postgres:$tag" >/dev/null
docker run -d --name "$id-redis" --network "$id" --network-alias redis \
    "$registry/ghostwriter_redis:$tag" >/dev/null

for _ in $(seq 1 60); do
    docker exec "$id-postgres" pg_isready -U postgres >/dev/null 2>&1 && break
    sleep 1
done

image="$registry/ghostwriter_django:$tag"
wheels="${GW_TEST_WHEELS:-${XDG_CACHE_HOME:-$HOME/.cache}/gw-fork-test-wheels/$tag}"
if ! ls "$wheels"/*.whl >/dev/null 2>&1; then
    requirement="$(grep -ioE '^factory-boy==[^ #]+' "$root/requirements/local.txt")"
    python_version="$(docker run --rm --entrypoint python "$image" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    mkdir -p "$wheels"
    python3 -m pip download --quiet --dest "$wheels" --only-binary=:all: \
        --python-version "$python_version" --implementation cp --platform manylinux2014_x86_64 \
        "$requirement"
fi

# Run as the invoking user so tests that write fixture files into the checkout can do so
django() {
    docker run --rm --network "$id" \
        -u "$(id -u):$(id -g)" -e HOME=/tmp \
        -e DJANGO_SETTINGS_MODULE=config.settings.test \
        -e DJANGO_ACCOUNT_EMAIL_VERIFICATION=none \
        -e DATABASE_URL="postgres://postgres:$password@postgres:5432/ghostwriter" \
        -e POSTGRES_HOST=postgres -e POSTGRES_PORT=5432 -e POSTGRES_DB=ghostwriter \
        -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD="$password" \
        -e REDIS_URL="redis://redis:6379/0" \
        -e SPACY_MODEL=en_core_web_sm \
        -e HASURA_ACTION_SECRET="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" \
        -v "$root":/app -v "$wheels":/wheels:ro -w /app --entrypoint sh "$image" -c \
        'pip install --quiet --user --no-index --find-links /wheels factory-boy >/dev/null && exec python manage.py "$@"' \
        manage "$@"
}

if [ "$#" -eq 0 ]; then
    echo "Checking for model changes without migrations"
    django makemigrations --check --dry-run
fi
django test --noinput --exclude-tag=GitHub "$@"
