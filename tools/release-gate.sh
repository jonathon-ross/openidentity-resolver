#!/usr/bin/env bash
set -euo pipefail

echo "========================================================================"
echo "OPENIDENTITY RESOLVER RELEASE GATE"
echo "========================================================================"

resolve_maven() {
  if command -v mvn >/dev/null 2>&1; then
    command -v mvn
    return
  fi

  if [[ -n "${MAVEN_HOME:-}" && -x "${MAVEN_HOME}/bin/mvn" ]]; then
    printf '%s\n' "${MAVEN_HOME}/bin/mvn"
    return
  fi

  if command -v cygpath >/dev/null 2>&1; then
    local fallback
    fallback="$(cygpath -u 'C:\\Users\\jonat\\apache-maven-3.9.16\\bin\\mvn.cmd')"
    if [[ -f "$fallback" ]]; then
      printf '%s\n' "$fallback"
      return
    fi
  fi

  echo "ERROR: Maven was not found. Add mvn to PATH or set MAVEN_HOME." >&2
  exit 1
}

MVN="$(resolve_maven)"
echo "Using Maven: $MVN"

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

"$MVN" spotless:check
"$MVN" clean verify
"$MVN" javadoc:javadoc

if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: release gate modified the worktree."
  git status --short
  exit 1
fi

echo "========================================================================"
echo "OPENIDENTITY RESOLVER RELEASE GATE: PASS"
echo "========================================================================"
