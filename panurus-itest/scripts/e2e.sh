#!/usr/bin/env bash
# End-to-end test of the RD/DFABI token network on the live Fabric-X network.
# Order: network health -> positive scenario -> negative tests -> privacy verification -> restart of a bank node
#        -> BI (auditor) offline -> final regression. Needs the nodes started (make live-start), KUBECONFIG for the ledger checks.
# Exit status 1 if any step failed. Full log: $RDBI_HOME/e2e-<timestamp>.log
set -uo pipefail
cd "$(dirname "$0")/.."
H="${RDBI_HOME:-$HOME/.fabricx-token}"; D="$H/bin/rdbi-driver"; LOG="$H/e2e-$(date +%Y%m%d-%H%M%S).log"
pass=0; fail=0; results=()
exec > >(tee "$LOG") 2>&1

step() { # name -- command...   (must succeed)
  local name="$1"; shift; local t0=$SECONDS
  if "$@" > "$H/.step.out" 2>&1; then pass=$((pass+1)); results+=("PASS  $name ($((SECONDS-t0))s)")
  else fail=$((fail+1)); results+=("FAIL  $name ($((SECONDS-t0))s)"); sed 's/\x1b\[[0-9;]*m//g' "$H/.step.out" | grep -vE ' (INFO|WARN) \[grpc\]| ERRO \[grpc\]|^\s+\||^\s+[a-z/].*\.go:[0-9]+$' | tail -12; fi
  sed 's/\x1b\[[0-9;]*m//g' "$H/.step.out" | grep -E '^(PASS|FAIL|INFO|SKIP|issue|transfer|DvP|burn|balance|BI audit|SCENARIO|NEGATIVE|PRIVACY)' || true
  echo "=> ${results[-1]}"; echo
}
step_fails() { # name -- command...   (must FAIL: the system has to refuse)
  local name="$1"; shift; local t0=$SECONDS
  if timeout 300 "$@" > "$H/.step.out" 2>&1; then fail=$((fail+1)); results+=("FAIL  $name: was accepted ($((SECONDS-t0))s)")
  else pass=$((pass+1)); results+=("PASS  $name: refused ($((SECONDS-t0))s)"); fi
  echo "=> ${results[-1]}"; echo
}
bal() { timeout 120 "$D" balance "$1" "$2" 2>&1 | tail -1; }
same() { [ "$(bal "$1" "$2")" = "$3" ]; }

echo "### 0. network and nodes"
step "five nodes and shim are running" bash -c '! ./scripts/run.sh status | grep -q DOWN'
ns_present() {
  [ "$(kubectl -n fabricx get pods --no-headers | grep -vc Running)" = 0 ] || return 1
  printf '%s\n' 'export PGPASSWORD=$POSTGRES_PASSWORD' \
    'psql -h 127.0.0.1 -p 5150 -U $POSTGRES_USER -d $POSTGRES_DB -Atc "select 1 from information_schema.tables where table_name = '"'"'ns_rd_dfabi'"'"'"' |
    kubectl -n fabricx exec -i committer-db-0 -- sh | grep -q 1
}
step "all fabricx pods Running and namespace rd_dfabi present on the committer" ns_present

echo "### 1. positive scenario (issue, transfer, DvP swap, burn, audit trail)"
step "scenario" "$D" scenario

echo "### 2. negative tests (must be refused, no balance may move)"
step "negative" "$D" negative

echo "### 3. privacy: who holds what, ledger opacity, endorser blindness"
step "privacy verification" python3 -I scripts/verify_privacy.py

echo "### 4. a bank node restarts and keeps its funds"
B2RD=$(bal bank2 RD); B3RD=$(bal bank3 RD)
./scripts/run.sh stop-node bank2; sleep 3; ./scripts/run.sh start-node bank2; sleep 30
step "bank2 balance survives a restart (RD=$B2RD)" same bank2 RD "$B2RD"
step "bank2 can send after the restart" "$D" transfer bank2 bank3 RD 5
step "balances moved by exactly 5" bash -c "[ \"\$($D balance bank2 RD | tail -1)\" = $((B2RD-5)) ] && [ \"\$($D balance bank3 RD | tail -1)\" = $((B3RD+5)) ]"

echo "### 5. BI (auditor) offline: no transaction may pass; back online it resumes"
B2RD=$(bal bank2 RD)
./scripts/run.sh stop-node issuer; sleep 3
step_fails "transfer while BI is offline" "$D" transfer bank2 bank3 RD 5
step "no balance moved while BI was offline" same bank2 RD "$B2RD"
./scripts/run.sh start-node issuer; sleep 30; "$D" register >/dev/null 2>&1
step "transfer works again once BI is back" "$D" transfer bank2 bank3 RD 5

echo "### 6. final regression and privacy after all the above"
step "scenario again" "$D" scenario
step "privacy verification again" python3 -I scripts/verify_privacy.py

echo "================ RESULT ================"
printf '%s\n' "${results[@]}"
echo "passed=$pass failed=$fail   log: $LOG"
[ "$fail" = 0 ]
