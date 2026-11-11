#!/usr/bin/env python3
"""Print the objects of the in-namespace S14 signing step of one org (fabricx S14 text (d), analyst conditions 1-9). stdout only, nothing is applied, no key read.

usage: render.py role <party>
       render.py job <party> --tx FILE --cacert FILE --image repo@sha256:HEX --tx-name NAME
`role`: Role s14-sign + RoleBinding in rd-fabricx-<party>: jobs create+get, pods get, pods/log get, bound to the org's own party-admin ServiceAccount only. TIME-BOXED: created right before the
org's signing and removed right after its Job completed (both logged in R13). party-admin cannot create a Role, so the operator creates it (R13).
`job`: ServiceAccount s14-signer (no token), ConfigMap s14-in-<NAME> (tx.json, the PUBLIC org CA cert, config.yaml for fxconfig), NetworkPolicy denying all traffic of the pod, Job s14-endorse-<NAME>:
one container of the tools image (digest) runs `fxconfig tx endorse /w/tx.json` and prints the partly signed tx to its log; the org's admin identity comes from the EXISTING Secret
orderer-admin-<N>-secret (keystore + signcert only) projected next to the ConfigMap items; nothing else is mounted. The key never leaves the namespace.
"""
import argparse, re, sys
import yaml

PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}
UID = 10001


def die(msg):
    sys.exit(f"render.py: {msg}")


def check(party):
    if party not in PARTY_N:
        die(f"party {party!r} must be one of {', '.join(PARTY_N)}")
    return PARTY_N[party], f"rd-fabricx-{party}"


def render_role(party):
    n, ns = check(party)
    meta = {"name": "s14-sign", "namespace": ns, "labels": LABELS}
    return yaml.safe_dump_all([
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta, "rules": [
            {"apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["create", "get"]},
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]},
            {"apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta,
         "subjects": [{"kind": "ServiceAccount", "name": "party-admin", "namespace": ns}],
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "s14-sign"}}], sort_keys=False)


def public_file(path, what):
    t = open(path).read()
    if "PRIVATE KEY" in t:
        die(f"{what} {path} holds a private key: only public data belongs in the input ConfigMap")
    return t


def render_job(party, tx, cacert, image, tx_name):
    n, ns = check(party)
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", tx_name or ""):
        die("--tx-name must be 1-30 chars of [a-z0-9-]")
    cm_name, job_name = f"s14-in-{tx_name}", f"s14-endorse-{tx_name}"
    pl = {**LABELS, "app.kubernetes.io/name": "s14-endorse"}
    meta = lambda name, extra=None: {"name": name, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(cm_name),
          "data": {"tx.json": public_file(tx, "--tx"), "ca.pem": public_file(cacert, "--cacert"),
                   "config.yaml": yaml.safe_dump({"msp": {"localMspID": f"org{n}", "configPath": "/w/msp"}}, sort_keys=False)}}
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("s14-signer"), "automountServiceAccountToken": False}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta("s14-endorse-deny-all"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "s14-endorse"}}, "policyTypes": ["Ingress", "Egress"]}}   # no rules: deny all
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    vol = {"name": "w", "projected": {"defaultMode": 0o440, "sources": [
        {"secret": {"name": f"orderer-admin-{n}-secret", "items": [{"key": "msp-keystore-priv_sk", "path": "msp/keystore/priv_sk"}, {"key": "msp-signcert.pem", "path": "msp/signcerts/cert.pem"}]}},
        {"configMap": {"name": cm_name, "items": [{"key": "tx.json", "path": "tx.json"}, {"key": "config.yaml", "path": "config.yaml"}, {"key": "ca.pem", "path": "msp/cacerts/ca.pem"}]}}]}}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(job_name, {"app.kubernetes.io/name": "s14-endorse"}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": pl}, "spec": {
                        "serviceAccountName": "s14-signer", "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": "endorse", "image": image, "command": ["fxconfig", "--config", "/w/config.yaml", "tx", "endorse", "/w/tx.json"],
                                        "securityContext": sec, "volumeMounts": [{"name": "w", "mountPath": "/w", "readOnly": True}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "128Mi", "ephemeral-storage": "16Mi"}}}],
                        "volumes": [vol]}}}}
    return yaml.safe_dump_all([cm, sa, np, job], sort_keys=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("what", choices=["role", "job"])
    ap.add_argument("party")
    for o in ("tx", "cacert", "image", "tx-name"):
        ap.add_argument(f"--{o}")
    a = ap.parse_args()
    if a.what == "role":
        sys.stdout.write(render_role(a.party))
    else:
        for o in ("tx", "cacert", "image", "tx_name"):
            if not getattr(a, o):
                die(f"--{o.replace('_', '-')} is required")
        sys.stdout.write(render_job(a.party, a.tx, a.cacert, a.image, a.tx_name))


if __name__ == "__main__":
    main()
