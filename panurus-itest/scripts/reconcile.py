#!/usr/bin/env python3
"""BI's completeness check of the banks' reports (detective control, see rdbi/report).

Every token transaction on the ledger leaves a token request key \\0tr\\0<txid>\\0 in the token namespace. Each
of them must have a confirmed record in BI's audit store (issuer node). Reads BI's committer DB in the cluster
(password stays inside the pod) and the issuer's SQLite store, read-only. Prints the gaps; exit 1 if any.
Env: KUBECONFIG, RDBI_HOME (default ~/.fabricx-token), NAMESPACE (default rd_dfabi).
"""
import os, sqlite3, subprocess, sys

H = os.environ.get("RDBI_HOME", os.path.expanduser("~/.fabricx-token"))
NS = os.environ.get("NAMESPACE", "rd_dfabi")

sql = f"select encode(key, 'escape') from ns_{NS}"
out = subprocess.check_output(["kubectl", "-n", "fabricx", "exec", "committer-db-0", "--", "sh", "-c",
                               f'PGPASSWORD=$POSTGRES_PASSWORD psql -U $POSTGRES_USER -d sc_db -p 5150 -h 127.0.0.1 -Atc "{sql}"'],
                              text=True)
prefix = "\\000tr\\000"
ledger = {k[len(prefix):len(prefix) + 64] for k in out.split() if k.startswith(prefix)}

db = sqlite3.connect(f"file:{os.path.join(H, 'live', 'issuer', 'data', 'default.sqlite')}?mode=ro", uri=True)
table = f"fsc_default__arma__{NS.replace('_', '__')}__aud_requests"
audit = dict(db.execute(f'select tx_id, status from "{table}"'))  # status 2 = confirmed against the ledger

gaps = sorted(tx for tx in ledger if audit.get(tx) != 2)
for tx in gaps:
    print(f"UNREPORTED tx {tx[:12]} (BI status: {audit.get(tx, 'no record')})")
print(f"reconcile: {len(ledger)} token transactions on the ledger, {len(ledger) - len(gaps)} confirmed in BI's audit store")
sys.exit(1 if gaps else 0)
