#!/usr/bin/env python3
"""Print the Role + RoleBinding that let BI's OWN party credential read the committer DB for reconcile (fabricx S17, analyst Q18). stdout only, nothing is applied.

usage: reconcile_role.py
TIME-BOXED R13 ONLY (applied by the operator right before the read, deleted right after, "RBAC left []" quoted; never a standing object: a standing copy was found live on 2026-11-12 and goes).
Role `reconcile` in rd-fabricx-bi: verbs EXACTLY `get` on pods and `create` on pods/exec, on exactly ONE pod name (committer-db-0), no list, no watch, no wildcard, nothing else. The FSC pod is NOT named:
it holds keys and nobody execs into it (orchestrator rule, 2026-11-12); read FSC state through its API/read path instead. RoleBinding subject: the ServiceAccount party-admin of rd-fabricx-bi only."""
import argparse, re, sys
import yaml

NS = "rd-fabricx-bi"
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx", "rd/r13": "time-boxed"}


def main():
    argparse.ArgumentParser(description=__doc__.split("\n")[0]).parse_args()
    names = ["committer-db-0"]
    meta = {"name": "reconcile", "namespace": NS, "labels": LABELS}
    docs = [{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta,
             "rules": [{"apiGroups": [""], "resources": ["pods"], "resourceNames": names, "verbs": ["get"]},
                       {"apiGroups": [""], "resources": ["pods/exec"], "resourceNames": names, "verbs": ["create"]}]},
            {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta,
             "subjects": [{"kind": "ServiceAccount", "name": "party-admin", "namespace": NS}],
             "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reconcile"}}]
    sys.stdout.write(yaml.safe_dump_all(docs, sort_keys=False))


if __name__ == "__main__":
    main()
