#!/bin/sh
# CodeSentinel scanner timing check.
# Run:  docker compose exec backend sh /app/app/diagnose.sh
SEMGREP="${SEMGREP_BIN:-/opt/semgrep/bin/semgrep}"
RULES="${RULES_DIR:-/app/rules}"
CACHE="${TRIVY_CACHE_DIR:-$HOME/.cache/trivy}"
WORK=$(mktemp -d)
cd "$WORK"
printf 'requests==2.19.1\n' > requirements.txt
printf 'import os\npassword = "abc12345"\nx = eval(input())\n' > app.py

echo "== memory (MB)"
awk '/MemTotal|MemAvailable|SwapTotal|SwapFree/ {printf "%s %d\n", $1, $2/1024}' /proc/meminfo
echo "== trivy database"
ls -la "$CACHE/db" 2>&1 | tail -3
echo "== timing (each limited to 120s)"

timeit() {
  name=$1; shift
  start=$(date +%s)
  timeout 120 "$@" >/dev/null 2>"$WORK/err.txt"
  code=$?
  echo "$name: $(( $(date +%s) - start ))s (exit $code)"
  if [ "$code" -ne 0 ]; then head -c 300 "$WORK/err.txt"; echo; fi
}

timeit gitleaks gitleaks dir . --no-banner --log-level error --exit-code 0
timeit trivy    trivy fs --scanners vuln --format json --quiet --offline-scan --skip-java-db-update --skip-db-update .
timeit semgrep  "$SEMGREP" scan --config "$RULES" --metrics=off --disable-version-check --quiet --json .
cd /; rm -rf "$WORK"
