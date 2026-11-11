#!/usr/bin/env python3
"""Print the objects of the in-namespace re-issue of ONE FSC identity cert (fabricx S13 fix: the p2p listener serves fsc/cert.pem, whose SAN must carry the names peers dial). stdout only, nothing applied.

usage: reenroll_render.py role <party>
       reenroll_render.py job <party> <node> --image repo@sha256:HEX --name GEN --api-cidr <ipv4>/32
`role`: SA fsc-reenroll + Role fsc-reenroll (ONLY secrets get+patch, resourceNames [rdbi-<pod>-files]) + RoleBinding. TIME-BOXED: the operator creates it right before the org's Job and removes it right after (R13 log).
`job`: NetworkPolicy + Job fsc-reenroll-<node>-<GEN> in rd-fabricx-<party>, applied by the org's OWN party-admin (the existing time-boxed s14-sign Role lets it create Jobs):
  image (digest, contains fabric-ca-client + the `fsc-reenroll` helper) runs `fabric-ca-client reenroll --csr.hosts <node>,<node>.<ns>.svc.cluster.local` authenticated by the CURRENT identity cert+key mounted from
  Secret rdbi-<pod>-files (two items), NO CA admin password and no FABRIC_CA_CLIENT_URL credentials; the new key is generated in the Job (memory emptyDir) and goes only into a merge-patch of the SAME Secret
  (keys own__<node>__fsc__cert.pem / ..__key.pem); the log carries exit codes, the Secret resourceVersion and the NEW PUBLIC cert only (the other orgs' resolvers need it).
  Pod label rd/egress-locked=true: egress ONLY own fca-org<N>:7054, the API server (--api-cidr, the kubernetes Service IP) :443 and DNS. The SA token is mounted (the helper PATCHes one Secret), this Job only.
"""
import argparse, re, sys
import yaml

PARTY = {"bi": (1, "bi", ["issuer", "endorser-1"]), "bank-a": (2, "bank2", ["bank2", "endorser-2"]), "bank-b": (3, "bank3", ["bank3", "endorser-3"]), "bank-c": (4, "bank4", ["bank4", "endorser-4"])}
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}
LOCK = "rd/egress-locked"
UID = 10001
NAMES = "C=US,ST=North Carolina,O=Hyperledger"


def die(msg):
    sys.exit(f"reenroll_render.py: {msg}")


def check(party):
    if party not in PARTY:
        die(f"party {party!r} must be one of {', '.join(PARTY)}")
    n, pod, nodes = PARTY[party]
    return n, pod, nodes, f"rd-fabricx-{party}"


def render_role(party):
    n, pod, nodes, ns = check(party)
    meta = {"name": "fsc-reenroll", "namespace": ns, "labels": LABELS}
    return yaml.safe_dump_all([
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta, "automountServiceAccountToken": False},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta,
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [f"rdbi-{pod}-files"], "verbs": ["get", "patch"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta,
         "subjects": [{"kind": "ServiceAccount", "name": "fsc-reenroll", "namespace": ns}], "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "fsc-reenroll"}}], sort_keys=False)


def egress(spec):
    if spec == "dns":
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}
    kind, val = spec
    if kind == "pod":
        return {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": val[0]}}}], "ports": [{"port": val[1], "protocol": "TCP"}]}
    return {"to": [{"ipBlock": {"cidr": val[0]}}], "ports": [{"port": val[1], "protocol": "TCP"}]}


def render_job(party, node, image, name, api_cidr):
    n, pod, nodes, ns = check(party)
    if node not in nodes:
        die(f"node {node!r} is not a node of {party} ({', '.join(nodes)})")
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,18}[a-z0-9])?", name or ""):
        die("--name must be 1-20 chars of [a-z0-9-]")
    m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})/32", api_cidr or "")
    if not m or any(int(x) > 255 for x in m.group(1).split(".")) or m.group(1) in ("0.0.0.0",):
        die("--api-cidr must be one <ipv4>/32 (the kubernetes Service IP), nothing wider")
    job_name, app = f"fsc-reenroll-{node}-{name}", f"fsc-reenroll-{node}-{name}"
    secret, keys = f"rdbi-{pod}-files", (f"own__{node}__fsc__cert.pem", f"own__{node}__fsc__key.pem")
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"],
                   "egress": [egress(("pod", (f"fca-org{n}", 7054))), egress(("ip", (api_cidr, 443))), egress("dns")]}}
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    cmd = ["fsc-reenroll", "--node", node, "--ca-url", f"http://fca-org{n}.{ns}.svc.cluster.local:7054", "--hosts", f"{node},{node}.{ns}.svc.cluster.local", "--names", NAMES,
           "--secret", secret, "--in", "/in", "--work", "/work", "--keys", ",".join(keys)]
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(job_name, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 180, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}}, "spec": {
                        "serviceAccountName": "fsc-reenroll", "automountServiceAccountToken": True, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": "reenroll", "image": image, "command": cmd, "securityContext": sec,
                                        "volumeMounts": [{"name": "in", "mountPath": "/in", "readOnly": True}, {"name": "work", "mountPath": "/work"}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "128Mi", "ephemeral-storage": "16Mi"}}}],
                        "volumes": [{"name": "in", "secret": {"secretName": secret, "defaultMode": 0o440, "items": [{"key": keys[0], "path": "cert.pem"}, {"key": keys[1], "path": "key.pem"}]}},
                                    {"name": "work", "emptyDir": {"medium": "Memory"}}]}}}}
    return yaml.safe_dump_all([np, job], sort_keys=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("what", choices=["role", "job"])
    ap.add_argument("party")
    ap.add_argument("node", nargs="?")
    for o in ("image", "name", "api-cidr"):
        ap.add_argument(f"--{o}")
    a = ap.parse_args()
    if a.what == "role":
        sys.stdout.write(render_role(a.party))
    else:
        if not (a.node and a.image and a.name and a.api_cidr):
            die("job needs <node> --image --name --api-cidr")
        sys.stdout.write(render_job(a.party, a.node, a.image, a.name, a.api_cidr))


if __name__ == "__main__":
    main()
