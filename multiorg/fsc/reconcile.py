#!/usr/bin/env python3
"""BI's completeness check of the banks' reports, per org namespace (fabricx S17; port of panurus-itest/scripts/reconcile.py). READ ONLY, one namespace.

usage: reconcile.py --kubeconfig K --fsc-pod rdbi-bi-<hash>-<id> [--ns rd-fabricx-bi] [--token-ns rd_dfabi_v2] [--committer-db committer-db-0] [--container issuer]
Every token transaction on the ledger leaves a token request key \\0tr\\0<txid>\\0 in the token namespace of BI's committer DB. Each of them must have a confirmed
record (status 2) in the issuer's audit store (SQLite on the state PVC of the FSC pod). Both are read with `kubectl exec` INSIDE the one namespace (the DB password is
expanded by the shell in the pod, never here); nothing is written, no other namespace is named. Needs pods/exec in that namespace (party-admin has none: run it with
a kubeconfig that has). The two pods are addressed by NAME (analyst Q18: the Role `reconcile` from reconcile_role.py names exactly them, verbs pods get + pods/exec create, no list/watch);
the FSC pod name changes at every rollout, so the Role is re-rendered with the new name in each FSC rollout (a failed run after a rollout = "Role stale", never retried under cluster-admin).
kubectl >= 1.31 execs over websockets by default, which needs `get` on pods/exec: SPDY is forced (KUBECTL_REMOTE_COMMAND_WEBSOCKETS=false) so `create` is enough. Prints the gaps; exit 1 if any.
"""
import argparse, os, re, sqlite3, subprocess, sys, tempfile

STORE = "/home/rdbi/.fabricx-token/live/issuer/data/default.sqlite"


def check_namespace(ns):
    if not re.fullmatch(r"[a-z0-9_]+", ns or ""):
        sys.exit(f"reconcile.py: token namespace {ns!r} must match [a-z0-9_]+")
    return ns


def ledger_txids(out):
    prefix = "\\000tr\\000"
    return {k[len(prefix):len(prefix) + 64] for k in out.split() if k.startswith(prefix)}


def audit_table(ns):
    return f"fsc_default__arma__{ns.replace('_', '__')}__aud_requests"


def gaps(ledger, audit):
    return sorted(tx for tx in ledger if audit.get(tx) != 2)   # status 2 = confirmed against the ledger


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--kubeconfig", required=True)
    ap.add_argument("--ns", default="rd-fabricx-bi")
    ap.add_argument("--token-ns", default="rd_dfabi_v2")
    ap.add_argument("--committer-db", default="committer-db-0")
    ap.add_argument("--fsc-pod", required=True)
    ap.add_argument("--container", default="issuer")
    a = ap.parse_args()
    tns = check_namespace(a.token_ns)
    if not re.fullmatch(r"rdbi-bi-[a-z0-9]+-[a-z0-9]+", a.fsc_pod):
        sys.exit(f"reconcile.py: --fsc-pod {a.fsc_pod!r} must be the BI FSC pod name rdbi-bi-<hash>-<id>")

    def ex(target, *cmd, container=None):
        c = ["kubectl", "--kubeconfig", a.kubeconfig, "-n", a.ns, "exec", target] + (["-c", container] if container else []) + ["--", "sh", "-c", *cmd]
        return subprocess.check_output(c, text=False, env={**os.environ, "KUBECTL_REMOTE_COMMAND_WEBSOCKETS": "false"})

    # the token namespace table exists only after S14 (namespace create): say so instead of a psql error and a traceback
    reg = ex(a.committer_db, f'PGPASSWORD=$POSTGRES_PASSWORD psql -U $POSTGRES_USER -d $POSTGRES_DB -h 127.0.0.1 -Atc "select to_regclass(\'ns_{tns}\')"').decode().strip()
    if not reg:
        print(f"reconcile: token namespace {tns} is not on the ledger yet (no table ns_{tns}): nothing to reconcile")
        sys.exit(2)
    sql = f"select encode(key, 'escape') from ns_{tns}"
    out = ex(a.committer_db, f'PGPASSWORD=$POSTGRES_PASSWORD psql -U $POSTGRES_USER -d $POSTGRES_DB -h 127.0.0.1 -Atc "{sql}"').decode()
    ledger = ledger_txids(out)
    d = tempfile.mkdtemp()
    local = os.path.join(d, "issuer.sqlite")
    # a consistent copy of the store: the database file and its write-ahead log (the log holds the latest records)
    with open(local, "wb") as f:
        f.write(ex(a.fsc_pod, f"cat {STORE}", container=a.container))
    with open(local + "-wal", "wb") as f:
        f.write(ex(a.fsc_pod, f"cat {STORE}-wal 2>/dev/null || true", container=a.container))
    audit = dict(sqlite3.connect(local).execute(f'select tx_id, status from "{audit_table(tns)}"'))
    bad = gaps(ledger, audit)
    for tx in bad:
        print(f"UNREPORTED tx {tx[:12]} (BI status: {audit.get(tx, 'no record')})")
    print(f"reconcile: {len(ledger)} token transactions on the ledger, {len(ledger) - len(bad)} confirmed in BI's audit store")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
