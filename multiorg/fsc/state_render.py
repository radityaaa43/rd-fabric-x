#!/usr/bin/env python3
"""Print the objects of an in-namespace Job that looks at / backs up / removes the sqlite of one org's FSC pod with the STOCK sqlite3 CLI (image fsc-sqlite-ci, no code of ours). stdout only, nothing applied.

usage: state_render.py <mode> <party> --image repo@sha256:HEX --name GEN        modes: count | b-prime | restore | remove-backup
The FSC pod keeps one sqlite per node on its state PVC `rdbi-<pod>-state`: `<PVC>/<node>/default.sqlite` (core.yaml persistences.default). The pod must be SCALED TO 0 first (clean close, no second writer, no WAL tearing).
  count          (A)  PVC mounted READ-ONLY. For each node: copy default.sqlite* to a scratch dir, checkpoint the COPY, `sqlite3 -readonly` the copy: prints `<node> <table> <rows>` and the file names. Never a value.
  b-prime        (B') per node, `set -eu`: counts of the original (via a copy) -> backup default.sqlite + -wal + -shm as *.bak-<GEN> (same PVC) with sha256 backup = original -> restore test (copy the backup to
                 .restore-test-<GEN>, counts must equal the first counts) -> remove the original three files. Any failure stops before the removal. PVC read-write.
  restore        rollback: copy the *.bak-<GEN> files back over default.sqlite* and verify sha256.
  remove-backup  the separate later step: remove ONLY the *.bak-<GEN> files.
                 The FSC pod keeps running: the state PVC is ReadWriteOnce and attached to its node, so this Job (only this mode) carries a required podAffinity to the FSC pod (same node);
                 without it the scheduler may pick another node and the Job dies with Multi-Attach (live 2026-11-12, bi).
Pod: label rd/egress-locked=true, NetworkPolicy with policyTypes Ingress+Egress and NO rules (all traffic denied), no Secret volume, no ServiceAccount token, uid 10001, deadline 120 s, ttl 900 s.
Scripts read $S (state, default /state) and $W (scratch, default /work) so they can be run on fixture directories in tests."""
import argparse, re, sys
import yaml

PARTY = {"bi": ("bi", ["issuer", "endorser-1"]), "bank-a": ("bank2", ["bank2", "endorser-2"]), "bank-b": ("bank3", ["bank3", "endorser-3"]), "bank-c": ("bank4", ["bank4", "endorser-4"])}
MODES = ("count", "b-prime", "restore", "remove-backup")
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}
LOCK = "rd/egress-locked"
UID = 10001


def die(msg):
    sys.exit(f"state_render.py: {msg}")


HEAD = 'set -eu\nS=${S:-/state}\nW=${W:-/work}\n'
CNT = '''cnt() { # prints "<table> <rows>" per table of the sqlite file $1 (opened read-only); never a value
  for t in $(sqlite3 -readonly "$1" "select name from sqlite_master where type='table' and name not like 'sqlite_%' order by name"); do
    echo "$t $(sqlite3 -readonly "$1" "select count(*) from \\"$t\\"")"
  done
}
scratch() { # $1 node: copy default.sqlite* of the node to $W/$1 and fold the WAL into the COPY
  mkdir -p "$W/$1"
  cp "$S/$1"/default.sqlite* "$W/$1/"
  sqlite3 "$W/$1/default.sqlite" "pragma wal_checkpoint(truncate)" >/dev/null 2>&1 || true
}
'''


def script(mode, nodes, gen):
    loop = f'for n in {" ".join(nodes)}; do\n  d="$S/$n"\n  [ -f "$d/default.sqlite" ] || {{ echo "$n NO-DB"; continue; }}\n'
    if mode == "count":
        return HEAD + CNT + loop + '  scratch "$n"\n  cnt "$W/$n/default.sqlite" | while read -r t c; do echo "$n $t $c"; done\n  echo "$n files: $(ls "$d" | tr \'\\n\' \' \')"\ndone\n'
    names = 'default.sqlite default.sqlite-wal default.sqlite-shm'
    if mode == "b-prime":
        return HEAD + CNT + loop + f'''  scratch "$n"
  cnt "$W/$n/default.sqlite" > "$W/$n.before"
  for f in {names}; do
    [ -f "$d/$f" ] || continue
    cp -p "$d/$f" "$d/$f.bak-{gen}"
    a=$(sha256sum < "$d/$f"); b=$(sha256sum < "$d/$f.bak-{gen}")
    [ "$a" = "$b" ] || {{ echo "$n $f backup differs"; exit 1; }}
  done
  echo "$n backup sha256 equal"
  r="$d/.restore-test-{gen}"
  mkdir "$r"
  for f in {names}; do
    [ -f "$d/$f.bak-{gen}" ] && cp "$d/$f.bak-{gen}" "$r/$f"
  done
  sqlite3 "$r/default.sqlite" "pragma wal_checkpoint(truncate)" >/dev/null 2>&1 || true
  cnt "$r/default.sqlite" > "$W/$n.after"
  cmp "$W/$n.before" "$W/$n.after" || {{ echo "$n restore test counts DIFFER"; exit 1; }}
  echo "$n restore test counts equal ($(wc -l < "$W/$n.after") tables)"
  rm -f "$r/default.sqlite" "$r/default.sqlite-wal" "$r/default.sqlite-shm"
  rmdir "$r"
  rm -f "$d/default.sqlite" "$d/default.sqlite-wal" "$d/default.sqlite-shm"
  echo "$n removed; files now: $(ls "$d" | tr '\\n' ' ')"
done
'''
    if mode == "restore":
        return HEAD + f'''for n in {" ".join(nodes)}; do
  d="$S/$n"
  [ -f "$d/default.sqlite.bak-{gen}" ] || {{ echo "$n no backup {gen}"; exit 1; }}
  for f in {names}; do
    [ -f "$d/$f.bak-{gen}" ] || continue
    cp -p "$d/$f.bak-{gen}" "$d/$f"
    a=$(sha256sum < "$d/$f"); b=$(sha256sum < "$d/$f.bak-{gen}")
    [ "$a" = "$b" ] || {{ echo "$n $f restore differs"; exit 1; }}
  done
  echo "$n restored from {gen}, sha256 equal"
done
'''
    return HEAD + f'''for n in {" ".join(nodes)}; do
  rm -f "$S/$n/default.sqlite.bak-{gen}" "$S/$n/default.sqlite-wal.bak-{gen}" "$S/$n/default.sqlite-shm.bak-{gen}"
  echo "$n backup {gen} removed; files now: $(ls "$S/$n" | tr '\\n' ' ')"
done
'''


def render(mode, party, image, gen):
    if party not in PARTY:
        die(f"party {party!r} must be one of {', '.join(PARTY)}")
    if mode not in MODES:
        die(f"mode must be one of {', '.join(MODES)}")
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?", gen or ""):
        die("--name must be 1-20 chars of [a-z0-9-]")
    pod, nodes = PARTY[party]
    ns = f"rd-fabricx-{party}"
    app = f"fsc-state-{mode}-{gen}"
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    ro = mode == "count"
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"]}}   # no rules: everything denied
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(app, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}}, "spec": {
                        "serviceAccountName": "s14-signer", "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        **({"affinity": {"podAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [
                            {"labelSelector": {"matchLabels": {"app.kubernetes.io/name": f"rdbi-{pod}"}}, "topologyKey": "kubernetes.io/hostname"}]}}} if mode == "remove-backup" else {}),
                        "containers": [{"name": "state", "image": image, "command": ["sh", "-c", script(mode, nodes, gen)], "securityContext": sec,
                                        "volumeMounts": [{"name": "state", "mountPath": "/state", **({"readOnly": True} if ro else {})}, {"name": "work", "mountPath": "/work"}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "64Mi"}}}],
                        "volumes": [{"name": "state", "persistentVolumeClaim": {"claimName": f"rdbi-{pod}-state", **({"readOnly": True} if ro else {})}},
                                    {"name": "work", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}]}}}}
    return yaml.safe_dump_all([np, job], sort_keys=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("mode")
    ap.add_argument("party")
    ap.add_argument("--image")
    ap.add_argument("--name")
    a = ap.parse_args()
    sys.stdout.write(render(a.mode, a.party, a.image, a.name))


if __name__ == "__main__":
    main()
