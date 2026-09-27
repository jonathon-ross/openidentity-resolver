#!/usr/bin/env bash
set -euo pipefail

echo "========================================================================"
echo "OPENIDENTITY RESOLVER RELEASE GATE"
echo "========================================================================"

cleanup() {
  docker compose rm -sf postgres-test >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: worktree must be clean before running the release gate."
  git status --short
  exit 1
fi

docker compose rm -sf postgres-test >/dev/null 2>&1 || true
docker compose up -d postgres-test

echo "Waiting for integration PostgreSQL..."
for _ in {1..30}; do
  if docker compose exec -T postgres-test pg_isready -U openidentity -d openidentity_test >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

docker compose exec -T postgres-test pg_isready -U openidentity -d openidentity_test >/dev/null

mvn spotless:check
mvn clean verify
mvn javadoc:javadoc

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: release gate modified the worktree."
  git status --short
  exit 1
fi

echo "========================================================================"
echo "OPENIDENTITY RESOLVER RELEASE GATE: PASS"
echo "========================================================================"
