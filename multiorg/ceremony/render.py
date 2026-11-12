#!/usr/bin/env python3
"""Print the objects of the in-namespace S14 signing step of one org (fabricx S14 text (d), analyst conditions 1-9). stdout only, nothing is applied, no key read.

usage: render.py role <party>
       render.py job <party> --tx FILE --cacert FILE --image repo@sha256:HEX --tx-name NAME
       render.py submit bi --tx FILE --cacert FILE --mspca FILE --image repo@sha256:HEX --tx-name NAME      (tx1 submit --wait, BI only)
       render.py readback bi --cacert FILE --mspca FILE --image repo@sha256:HEX --tx-name NAME              (`namespace list`, every party: its own committer-tls and query service)
       render.py setuppp bi --image repo@sha256:HEX --name NAME [--namespace rd_dfabi_v2]       (rdbi-driver setup-pp, BI only)
       render.py dbread <party> --name NAME --mode schema|status|occurrences [--txid HEX64] [--needle HEX] [--namespace rd_dfabi_v2]   (egress-locked read-only psql Job on the org's own committer-db; no exec)
       render.py p2psan <party> --image repo@sha256:HEX --name NAME --cacert PEM --check PARTY/NODE@HOST:PORT ... --allow SPEC ... [--alias IP=host,host ...]   (p2p_san as a keyless in-cluster Job)
       render.py probe <party> --image repo@sha256:HEX --name NAME --try LABEL=HOST:PORT ... [--allow pod=APP:PORT | --allow dns ...]
`role`: Role s14-sign + RoleBinding in rd-fabricx-<party>: jobs create+get, pods get, pods/log get, bound to the org's own party-admin ServiceAccount only. TIME-BOXED: created right before the
org's signing and removed right after its Job completed (both logged in R13). party-admin cannot create a Role, so the operator creates it (R13).
`job`: ServiceAccount s14-signer (no token), ConfigMap s14-in-<NAME> (tx.json, the PUBLIC org CA cert, config.yaml for fxconfig), NetworkPolicy denying all traffic of the pod, Job s14-endorse-<NAME>:
one container of the tools image (digest) runs `fxconfig tx endorse /w/tx.json` and prints the partly signed tx to its log; the org's admin identity comes from the EXISTING Secret
orderer-admin-<N>-secret (keystore + signcert only) projected next to the ConfigMap items; nothing else is mounted. The key never leaves the namespace.
EGRESS (R16): the namespace policy allow-dns-egress selects every pod WITHOUT the label rd/egress-locked and allows all egress, and K8s policies are additive. Every Job pod that mounts a
Secret therefore carries rd/egress-locked=true (check_locked refuses a render without it), so its own NetworkPolicy is the only egress it gets.
`submit`/`readback` (orchestrator S1, BI only): the router, sidecar and query service speak mTLS, so besides the org MSP key (submit only) the Job mounts the committer's TLS identity, the Secret
committer-tls (server.crt/server.key/ca.crt as the TLS client cert/key/CA; EKU has clientAuth), read-only, plus ONE ConfigMap (the public tx, config, the public router CA). Egress (own policy, the pod carries
the lock label): submit = router :8013 + sidecar :5130 + DNS; readback = query :5140 + DNS. Nothing else. Files are 0440 (root-owned, group = fsGroup): 0400 would be unreadable for uid 10001.
`setuppp` (qa finding f; BI only): the one-shot `rdbi-driver setup-pp` as a Job under BI's own party-admin instead of an exec with cluster-admin. It mounts only what the BI gateway Deployment already
mounts for the same client identity: CM fx-gw-1-client (client-config + the gateway public cert + the PUBLIC public-params.bin), Secret fx-gw-1-client key gw.key, CM rdbi-public ca-bundle.pem. Egress (own
policy, lock label): the issuer FSC view port :5100 + DNS. The issuer node itself talks to the orderer/committer, not the Job.
`probe`: a Job that mounts NO Secret, carries the label and tries TCP connects (bash /dev/tcp, 4 s each), printing `LABEL HOST:PORT OPEN|CLOSED`; its own policy allows only the --allow entries
(pod=<app.kubernetes.io/name>:<port> in the same namespace, ip=<ipv4>/32:<port> one external host, nspod=<rd-fabricx-ns>/<app>:<port> a pod of another rd-fabricx namespace, dns = kube-system :53). It proves the policy binds before any key-holding Job relies on it.
"""
import argparse, hashlib, json, re, sys
import yaml

PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}
UID = 10001
LOCK = "rd/egress-locked"


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


def check_locked(docs):
    """Refuse a render where a Job pod mounts a Secret but lacks the egress-lock label (R16)."""
    for d in docs:
        if d["kind"] != "Job":
            continue
        pod = d["spec"]["template"]
        mounts = any("secret" in v or any("secret" in src for src in v.get("projected", {}).get("sources", [])) for v in pod["spec"].get("volumes", []))
        if mounts and pod["metadata"]["labels"].get(LOCK) != "true":
            die(f"Job {d['metadata']['name']} mounts a Secret but its pod lacks the label {LOCK}=true: allow-dns-egress would leave its egress open")


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
    pl = {**LABELS, "app.kubernetes.io/name": "s14-endorse", LOCK: "true"}
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
    check_locked([job])
    return yaml.safe_dump_all([cm, sa, np, job], sort_keys=False)


def egress_rule(spec):
    if spec == "dns":
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}], "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}
    nsp = re.fullmatch(r"nspod=(rd-fabricx-[a-z0-9-]+)/([a-z0-9]([a-z0-9-]*[a-z0-9])?):(\d{1,5})", spec)
    if nsp:   # another rd-fabricx-* namespace's pod, by selectors (ipBlock does not match in-cluster pod IPs on this CNI: live probes 2026-11-11 p3pre)
        if not 0 < int(nsp.group(4)) < 65536:
            die(f"--allow {spec!r}: bad port")
        return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": nsp.group(1)}}, "podSelector": {"matchLabels": {"app.kubernetes.io/name": nsp.group(2)}}}],
                "ports": [{"port": int(nsp.group(4)), "protocol": "TCP"}]}
    ip = re.fullmatch(r"ip=(\d{1,3}(?:\.\d{1,3}){3})/32:(\d{1,5})", spec)
    if ip:   # one host, one port: the API-server / LB probes of the FSC re-issue
        if any(int(x) > 255 for x in ip.group(1).split(".")) or ip.group(1) == "0.0.0.0" or not 0 < int(ip.group(2)) < 65536:
            die(f"--allow {spec!r}: bad address or port")
        return {"to": [{"ipBlock": {"cidr": ip.group(1) + "/32"}}], "ports": [{"port": int(ip.group(2)), "protocol": "TCP"}]}
    m = re.fullmatch(r"pod=([a-z0-9]([a-z0-9-]*[a-z0-9])?):(\d{1,5})", spec)
    if not m or not 0 < int(m.group(3)) < 65536:
        die(f"--allow {spec!r} must be dns or pod=<app.kubernetes.io/name>:<port 1-65535>")
    return {"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/name": m.group(1)}}}], "ports": [{"port": int(m.group(3)), "protocol": "TCP"}]}


def render_probe(party, image, name, tries, allow):
    n, ns = check(party)
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", name or ""):
        die("--name must be 1-30 chars of [a-z0-9-]")
    if not tries or not all(re.fullmatch(r"[a-z0-9-]+=[A-Za-z0-9.-]+:\d{1,5}", t) for t in tries):
        die("--try must be LABEL=HOST:PORT, at least one")
    app = f"s14-probe-{name}"
    pl = {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"]}}
    if allow:
        np["spec"]["egress"] = [egress_rule(a) for a in allow]
    script = 'for t in "$@"; do n=${t%%=*}; hp=${t#*=}; if timeout 4 bash -c "exec 3<>/dev/tcp/${hp%:*}/${hp##*:}" 2>/dev/null; then echo "$n $hp OPEN"; else echo "$n $hp CLOSED"; fi; done'
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(app, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": pl}, "spec": {
                        "serviceAccountName": "s14-signer", "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": "probe", "image": image, "command": ["bash", "-c", script, "probe", *tries], "securityContext": sec,
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "200m", "memory": "64Mi", "ephemeral-storage": "16Mi"}}}]}}}}
    check_locked([job])
    return yaml.safe_dump_all([np, job], sort_keys=False)


NET_TLS_SECRET = "committer-tls"
NET_EGRESS = {"submit": ["pod=orderer-router-1:8013", "pod=committer-sidecar:5130", "dns"], "readback": ["pod=committer-query:5140", "dns"]}


def render_net(kind, party, image, tx_name, cacert, mspca, tx=None):
    if kind not in NET_EGRESS:
        die(f"kind {kind!r} must be one of {', '.join(NET_EGRESS)}")
    if party != "bi" and kind == "submit":
        die("submit is rendered for BI only (orchestrator S1: BI's own committer-tls and org1 key); readback is rendered for every party with that party's own committer-tls")
    n, ns = check(party)
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", tx_name or ""):
        die("--tx-name must be 1-30 chars of [a-z0-9-]")
    app, cm_name = f"s14-{kind}", f"s14-{kind}-in-{tx_name}"
    job_name = f"{app}-{tx_name}"
    cfg = {"msp": {"localMspID": f"org{n}", "configPath": "/w/msp"},
           "tls": {"enabled": True, "clientCert": "/w/tls/client.crt", "clientKey": "/w/tls/client.key", "rootCerts": ["/w/tlsca.pem", "/w/tls/ca.crt"]},
           "orderer": {"address": f"lb-{n}:8013", "channel": "arma", "connectionTimeout": "15s", "tls": {"serverNameOverride": f"router-{n}.arma.rd"}},
           "queries": {"address": "committer-query-service:5140", "connectionTimeout": "15s"},
           "notifications": {"address": "committer-sidecar:5130", "connectionTimeout": "15s", "waitingTimeout": "60s"}}
    if not mspca:
        die("--mspca is required (the org MSP CA certificate, public: fxconfig loads the MSP from /w/msp and needs msp/cacerts/)")
    data = {"config.yaml": yaml.safe_dump(cfg, sort_keys=False), "tlsca.pem": public_file(cacert, "--cacert"), "mspca.pem": public_file(mspca, "--mspca")}
    items = [{"key": "config.yaml", "path": "config.yaml"}, {"key": "tlsca.pem", "path": "tlsca.pem"}, {"key": "mspca.pem", "path": "msp/cacerts/ca.pem"}]
    sources = []
    if kind == "submit":
        if not tx:
            die("--tx is required for submit")
        data["tx.json"] = public_file(tx, "--tx")
        items.append({"key": "tx.json", "path": "tx.json"})
        sources.append({"secret": {"name": f"orderer-admin-{n}-secret", "items": [{"key": "msp-keystore-priv_sk", "path": "msp/keystore/priv_sk"}, {"key": "msp-signcert.pem", "path": "msp/signcerts/cert.pem"}]}})
        cmd = ["fxconfig", "--config", "/w/config.yaml", "tx", "submit", "/w/tx.json", "--wait"]
    else:
        cmd = ["fxconfig", "--config", "/w/config.yaml", "namespace", "list"]
    sources.append({"secret": {"name": NET_TLS_SECRET, "items": [{"key": "server.crt", "path": "tls/client.crt"}, {"key": "server.key", "path": "tls/client.key"}, {"key": "ca.crt", "path": "tls/ca.crt"}]}})
    sources.append({"configMap": {"name": cm_name, "items": items}})
    meta = lambda name, extra=None: {"name": name, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    pl = {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(cm_name), "data": data}
    sa = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta("s14-signer"), "automountServiceAccountToken": False}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"], "egress": [egress_rule(a) for a in NET_EGRESS[kind]]}}
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(job_name, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": pl}, "spec": {
                        "serviceAccountName": "s14-signer", "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": kind, "image": image, "command": cmd, "securityContext": sec, "volumeMounts": [{"name": "w", "mountPath": "/w", "readOnly": True}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "128Mi", "ephemeral-storage": "16Mi"}}}],
                        "volumes": [{"name": "w", "projected": {"defaultMode": 0o440, "sources": sources}}]}}}}
    check_locked([job])
    return yaml.safe_dump_all([cm, sa, np, job], sort_keys=False)


def render_setuppp(party, image, name, namespace="rd_dfabi_v2"):
    if party != "bi":
        die("setuppp is rendered for BI only (the issuer node installs the public parameters)")
    n, ns = check(party)
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", name or ""):
        die("--name must be 1-30 chars of [a-z0-9-]")
    if not re.fullmatch(r"[A-Za-z0-9_]{1,40}", namespace or ""):
        die("--namespace must be 1-40 chars of [A-Za-z0-9_]")
    app, home = "s14-setuppp", "/home/rdbi"
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"], "egress": [egress_rule("pod=rdbi-bi:5100"), egress_rule("dns")]}}
    live = {"name": "live", "projected": {"defaultMode": 0o440, "sources": [
        {"configMap": {"name": "fx-gw-1-client", "items": [{"key": "client-config.yaml", "path": "live/issuer/client-config.yaml"}, {"key": "issuer-gw.pem", "path": "gw/issuer-gw.pem"}, {"key": "public-params.bin", "path": "live/public-params.bin"}]}},
        {"secret": {"name": "fx-gw-1-client", "items": [{"key": "gw.key", "path": "gw/issuer-gw.key"}]}},
        {"configMap": {"name": "rdbi-public", "items": [{"key": "ca-bundle.pem", "path": "live/issuer/tls-ca.crt"}]}}]}}
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(f"{app}-{name}", {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 180, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}}, "spec": {
                        "serviceAccountName": "s14-signer", "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "imagePullSecrets": [{"name": "ghcr-pull"}],
                        "containers": [{"name": "setup-pp", "image": image, "command": ["rdbi-driver", "setup-pp"],
                                        "env": [{"name": "HOME", "value": home}, {"name": "NAMESPACE", "value": namespace}], "securityContext": sec,
                                        "volumeMounts": [{"name": "home", "mountPath": home}, {"name": "live", "mountPath": f"{home}/.fabricx-token", "readOnly": True}],
                                        "resources": {"requests": {"cpu": "20m", "memory": "64Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "32Mi"}}}],
                        "volumes": [{"name": "home", "emptyDir": {}}, live]}}}}
    check_locked([job])
    return yaml.safe_dump_all([np, job], sort_keys=False)


PG_IMAGE = "docker.io/library/postgres@sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317"   # the digest committer-db already runs (multiorg/committer/render.py PG_IMAGE)
# `dbread` (no exec into key holders): the three statements it can ever run. {ns} = ns_<namespace>; txid / needle are validated lowercase hex embedded at RENDER time (no psql variables: -c does not interpolate them).
# UNVERIFIED until a `schema` run: the column names (tx_id, status, key, value); the first live use is `schema`, and a changed statement changes dbread_template_sha256 (the GO text quotes it).
DBREAD_SQL = {
    "schema": "select table_name || '.' || column_name || ':' || data_type from information_schema.columns where table_name in ('tx_status', '{ns}') order by table_name, ordinal_position",
    "status": "select status from tx_status where tx_id = decode('{txid}', 'hex')",
    "occurrences": "select count(*) from {ns} where position(decode('{txid}', 'hex') in key) > 0 and position(decode('{needle}', 'hex') in value) > 0",
}
DBREAD_FLAGS = ["-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-c"]
DBREAD_ENV = ["PGHOST", "PGPORT", "PGDATABASE", "PGUSER", "PGSSLMODE", "PGCONNECT_TIMEOUT", "PGPASSWORD"]
DBREAD_WRITE = re.compile(r"\b(insert|update|delete|drop|create|alter|grant|revoke|truncate|copy|call|vacuum|set|reset|lock|do)\b|;|pg_read_file|lo_import|dblink", re.I)


def dbread_sql(mode, namespace, txid=None, needle=None):
    if mode not in DBREAD_SQL:
        die(f"mode must be one of {', '.join(DBREAD_SQL)}")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,40}", namespace or ""):
        die("--namespace must match [a-z][a-z0-9_]{0,40}")
    if mode != "schema" and not re.fullmatch(r"[0-9a-f]{64}", txid or ""):
        die("--txid must be 64 lowercase hex characters")
    if mode == "occurrences" and not re.fullmatch(r"([0-9a-f]{2}){1,8}", needle or ""):
        die("--needle must be 1-8 bytes of lowercase hex")
    return DBREAD_SQL[mode].format(ns="ns_" + namespace, txid=txid, needle=needle)


def dbread_template_sha256(namespace):
    """sha256 over the three statement TEMPLATES for this namespace (placeholders kept): the 'fixed script' the GO text quotes."""
    t = {m: q.format(ns="ns_" + namespace, txid="{txid}", needle="{needle}") for m, q in DBREAD_SQL.items()}
    return hashlib.sha256(json.dumps(t, sort_keys=True).encode()).hexdigest()


def render_dbread(party, name, mode, txid=None, needle=None, namespace="rd_dfabi_v2"):
    n, ns = check(party)
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", name or ""):
        die("--name must be 1-30 chars of [a-z0-9-]")
    sql = dbread_sql(mode, namespace, txid, needle)
    app = f"dbread-{name}"
    pl = {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"], "egress": [egress_rule("dns"), egress_rule("pod=committer-db:5432")]}}
    env = [{"name": "PGHOST", "value": "committer-db"}, {"name": "PGPORT", "value": "5432"}, {"name": "PGDATABASE", "value": "committer"}, {"name": "PGUSER", "value": "committer"},
           {"name": "PGSSLMODE", "value": "require"}, {"name": "PGCONNECT_TIMEOUT", "value": "5"},
           {"name": "PGPASSWORD", "valueFrom": {"secretKeyRef": {"name": "committer-db-credentials", "key": "password"}}}]
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(app, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 120, "ttlSecondsAfterFinished": 900,
                    "template": {"metadata": {"labels": pl}, "spec": {
                        "automountServiceAccountToken": False, "restartPolicy": "Never",
                        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
                        "containers": [{"name": "dbread", "image": PG_IMAGE, "command": ["psql"], "args": [*DBREAD_FLAGS, sql], "env": env, "securityContext": sec,
                                        "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "200m", "memory": "64Mi", "ephemeral-storage": "16Mi"}}}]}}}}
    check_locked([job])
    docs = [np, job]
    problems = audit_dbread(docs, mode)
    if problems:
        die("dbread audit: " + "; ".join(problems))
    return yaml.safe_dump_all(docs, sort_keys=False)


def audit_dbread(docs, mode):
    """Problems (empty = fine) for a dbread render: a keyless-to-the-API, egress-locked, SELECT-only reader that can print only a status string, integers or column names."""
    p = []
    nps, jobs = [d for d in docs if d["kind"] == "NetworkPolicy"], [d for d in docs if d["kind"] == "Job"]
    if len(nps) != 1 or len(jobs) != 1 or len(docs) != 2:
        return ["not exactly one NetworkPolicy and one Job"]
    np, job = nps[0], jobs[0]
    t = job["spec"]["template"]; ps = t["spec"]; cs = ps.get("containers", [])
    if len(cs) != 1:
        return ["not exactly one container"]
    c = cs[0]; labels = t["metadata"]["labels"]
    if labels.get(LOCK) != "true":
        p.append("rd/egress-locked label missing")
    if np["spec"]["podSelector"].get("matchLabels") != {"app.kubernetes.io/name": labels.get("app.kubernetes.io/name")}:
        p.append("NetworkPolicy does not select the Job pod")
    if np["spec"].get("policyTypes") != ["Ingress", "Egress"] or "ingress" in np["spec"] or np["spec"].get("egress") != [egress_rule("dns"), egress_rule("pod=committer-db:5432")]:
        p.append("egress is not exactly kube-dns + committer-db:5432 (or ingress rules present)")
    if c.get("image") != PG_IMAGE:
        p.append("image is not the pinned postgres digest")
    if c.get("command") != ["psql"]:
        p.append("command is not exactly [psql] (no shell)")
    args = c.get("args", [])
    sql = args[-1] if args else ""
    if args[:-1] != DBREAD_FLAGS:
        p.append("psql flags differ")
    if DBREAD_WRITE.search(sql) or not sql.lstrip().lower().startswith("select "):
        p.append("SQL is not a single read-only SELECT")
    pat = re.escape(DBREAD_SQL.get(mode, "")).replace(re.escape("{ns}"), r"ns_[a-z][a-z0-9_]{0,40}").replace(re.escape("{txid}"), r"[0-9a-f]{64}").replace(re.escape("{needle}"), r"([0-9a-f]{2}){1,8}")
    if not re.fullmatch(pat, sql):
        p.append("SQL is not the fixed statement of this mode")
    env = c.get("env", [])
    if [e["name"] for e in env] != DBREAD_ENV:
        p.append("env names differ")
    refs = [(e["name"], e["valueFrom"]) for e in env if "valueFrom" in e]
    if refs != [("PGPASSWORD", {"secretKeyRef": {"name": "committer-db-credentials", "key": "password"}})]:
        p.append("secret references other than PGPASSWORD <- committer-db-credentials/password")
    if "volumes" in ps or "volumeMounts" in c or "envFrom" in c or ps.get("automountServiceAccountToken") is not False or ps.get("serviceAccountName"):
        p.append("volume / envFrom / service account token present")
    sp = job["spec"]
    if (sp.get("backoffLimit"), sp.get("ttlSecondsAfterFinished"), ps.get("restartPolicy")) != (0, 900, "Never") or not 0 < sp.get("activeDeadlineSeconds", 0) <= 120:
        p.append("Job lifetime fields differ")
    return p


P2PSAN_SCRIPT = r"""set +e
command -v openssl >/dev/null || { echo "NO_OPENSSL in this image"; exit 3; }
for t in "$@"; do
  party=${t%%/*}; rest=${t#*/}; node=${rest%%@*}; hp=${rest#*@}; ns=rd-fabricx-$party
  out=$(timeout 15 openssl s_client -connect "$hp" -servername "$node" -CAfile /ca/ca.pem -verify_hostname "$node" </dev/null 2>/dev/null)
  if ! printf '%s' "$out" | grep -q 'BEGIN CERTIFICATE'; then echo "$party $node: no certificate presented from $hp"; continue; fi
  cert=$(printf '%s\n' "$out" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p;/END CERTIFICATE/q')
  names=$(printf '%s\n' "$cert" | openssl x509 -noout -ext subjectAltName 2>/dev/null | tr ',' '\n' | sed -n 's/^ *DNS://p' | tr '\n' ' ')
  fp=$(printf '%s\n' "$cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2)
  miss=""; for want in "$node" "$node.$ns.svc.cluster.local"; do case " $names" in *" $want "*) ;; *) miss="$miss $want";; esac; done
  v=$(printf '%s\n' "$out" | sed -n 's/^.*Verify return code: \([0-9]*\) (\(.*\))$/\1:\2/p' | tail -1)
  if [ "$v" = "0:ok" ]; then vv="verify OK"; else vv="verify FAIL $v"; fi
  if [ -z "$miss" ]; then nm="OK"; else nm="MISSING$miss"; fi
  echo "$party $node: SAN [$names] $nm | $vv | sha256 $fp"
done
"""   # prints one line per endpoint in the shape of p2p_san.py live: only SAN names, OK/MISSING, verify result and the PUBLIC cert fingerprint


def render_p2psan(party, image, name, checks, allow, aliases, cacert):
    """p2p_san.py as a keyless in-cluster Job: the P2P listeners are checked FROM a pod that carries the egress lock and may reach exactly the listed endpoints (no host port-forward)."""
    n, ns = check(party)
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", image or ""):
        die("--image must be pinned by digest (repo@sha256:<64 hex>)")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9-]{0,28}[a-z0-9])?", name or ""):
        die("--name must be 1-30 chars of [a-z0-9-]")
    if not checks or not all(re.fullmatch(r"(bi|bank-a|bank-b|bank-c)/[a-z0-9][a-z0-9-]*@[A-Za-z0-9.-]+:\d{1,5}", c) and 0 < int(c.rsplit(":", 1)[1]) < 65536 for c in checks):
        die("--check must be PARTY/NODE@HOST:PORT, at least one")
    if not allow:
        die("--allow is required (every endpoint needs its rule)")
    al = []
    for a in aliases or []:
        m = re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3})=([A-Za-z0-9.,-]+)", a)
        if not m or any(int(x) > 255 for x in m.group(1).split(".")):
            die(f"--alias {a!r} must be IPV4=host[,host...]")
        al.append({"ip": m.group(1), "hostnames": m.group(2).split(",")})
    pem = open(cacert).read()
    if "PRIVATE KEY" in pem or "BEGIN CERTIFICATE" not in pem:
        die("--cacert must hold PUBLIC certificates only")
    app = f"p2psan-{name}"
    pl = {**LABELS, "app.kubernetes.io/name": app, LOCK: "true"}
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}
    cm = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"{app}-ca"), "data": {"ca.pem": pem}}
    np = {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(f"{app}-egress"),
          "spec": {"podSelector": {"matchLabels": {"app.kubernetes.io/name": app}}, "policyTypes": ["Ingress", "Egress"], "egress": [egress_rule(a) for a in allow]}}
    sec = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}
    spec = {"automountServiceAccountToken": False, "restartPolicy": "Never",
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": [{"name": "p2psan", "image": image, "command": ["bash", "-c", P2PSAN_SCRIPT, "p2psan", *checks], "securityContext": sec,
                            "volumeMounts": [{"name": "ca", "mountPath": "/ca", "readOnly": True}],
                            "resources": {"requests": {"cpu": "20m", "memory": "32Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "200m", "memory": "64Mi", "ephemeral-storage": "16Mi"}}}],
            "volumes": [{"name": "ca", "configMap": {"name": f"{app}-ca"}}]}
    if al:
        spec["hostAliases"] = al
    job = {"apiVersion": "batch/v1", "kind": "Job", "metadata": meta(app, {"app.kubernetes.io/name": app}),
           "spec": {"backoffLimit": 0, "activeDeadlineSeconds": 180, "ttlSecondsAfterFinished": 900, "template": {"metadata": {"labels": pl}, "spec": spec}}}
    check_locked([job])
    docs = [cm, np, job]
    problems = audit_p2psan(docs)
    if problems:
        die("p2psan audit: " + "; ".join(problems))
    return yaml.safe_dump_all(docs, sort_keys=False)


def audit_p2psan(docs):
    """Problems (empty = fine): public CA only, no Secret, pinned image, the fixed script, egress-locked with ONLY the endpoint rules (no DNS, no extra destination)."""
    p = []
    kinds = sorted(d["kind"] for d in docs)
    if kinds != ["ConfigMap", "Job", "NetworkPolicy"]:
        return ["not exactly one ConfigMap, NetworkPolicy and Job"]
    cm, np, job = [next(d for d in docs if d["kind"] == k) for k in ("ConfigMap", "NetworkPolicy", "Job")]
    if set(cm.get("data", {})) != {"ca.pem"} or "PRIVATE KEY" in cm["data"]["ca.pem"] or "BEGIN CERTIFICATE" not in cm["data"]["ca.pem"]:
        p.append("CA ConfigMap is not public certificates only")
    t = job["spec"]["template"]; ps = t["spec"]; cs = ps.get("containers", [])
    if len(cs) != 1:
        return p + ["not exactly one container"]
    c = cs[0]
    if t["metadata"]["labels"].get(LOCK) != "true":
        p.append("rd/egress-locked label missing")
    if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", c.get("image", "")):
        p.append("image is not pinned by digest")
    if c.get("command", [None] * 3)[:3] != ["bash", "-c", P2PSAN_SCRIPT]:
        p.append("script differs from the pinned one")
    if "env" in c or "envFrom" in c or ps.get("automountServiceAccountToken") is not False or ps.get("serviceAccountName"):
        p.append("env / service account token present")
    vols = ps.get("volumes", [])
    if len(vols) != 1 or set(vols[0]) != {"name", "configMap"} or "secret" in yaml.safe_dump(t).lower():
        p.append("volumes other than the one CA ConfigMap, or a secret reference")
    rules = np["spec"].get("egress", [])
    ports = {r_["port"] for r in rules for r_ in r["ports"]}
    want = {int(x.rsplit(":", 1)[1]) for x in c.get("command", [])[4:]}
    if "ingress" in np["spec"] or np["spec"].get("policyTypes") != ["Ingress", "Egress"] or ports != want or any(53 in [r_["port"] for r_ in r["ports"]] for r in rules):
        p.append("egress is not exactly the endpoint ports (no DNS, no extra port/destination)")
    if len(rules) != len({yaml.safe_dump(r) for r in rules}):
        p.append("duplicate egress rule")
    sp = job["spec"]
    if (sp.get("backoffLimit"), sp.get("ttlSecondsAfterFinished"), ps.get("restartPolicy")) != (0, 900, "Never") or not 0 < sp.get("activeDeadlineSeconds", 0) <= 180:
        p.append("Job lifetime fields differ")
    return p


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("what", choices=["role", "job", "probe", "submit", "readback", "setuppp", "dbread", "p2psan"])
    ap.add_argument("party")
    for o in ("tx", "cacert", "image", "tx-name", "name"):
        ap.add_argument(f"--{o}")
    ap.add_argument("--mspca")
    ap.add_argument("--namespace", default="rd_dfabi_v2")
    ap.add_argument("--try", dest="tries", action="append", default=[])
    ap.add_argument("--allow", action="append", default=[])
    ap.add_argument("--mode")
    ap.add_argument("--check", action="append", default=[])
    ap.add_argument("--alias", action="append", default=[])
    ap.add_argument("--txid")
    ap.add_argument("--needle")
    a = ap.parse_args()
    if a.what == "role":
        sys.stdout.write(render_role(a.party))
    elif a.what in ("submit", "readback"):
        for o in ("image", "tx_name", "cacert") + (("tx",) if a.what == "submit" else ()):
            if not getattr(a, o):
                die(f"--{o.replace('_', '-')} is required")
        sys.stdout.write(render_net(a.what, a.party, a.image, a.tx_name, a.cacert, a.mspca, a.tx))
    elif a.what == "setuppp":
        for o in ("image", "name"):
            if not getattr(a, o):
                die(f"--{o} is required")
        sys.stdout.write(render_setuppp(a.party, a.image, a.name, a.namespace))
    elif a.what == "p2psan":
        if not a.name or not a.image or not a.cacert:
            die("--name, --image and --cacert are required")
        sys.stdout.write(render_p2psan(a.party, a.image, a.name, a.check, a.allow, a.alias, a.cacert))
    elif a.what == "dbread":
        if not a.name or not a.mode:
            die("--name and --mode are required")
        sys.stdout.write(render_dbread(a.party, a.name, a.mode, a.txid, a.needle, a.namespace))
    elif a.what == "probe":
        sys.stdout.write(render_probe(a.party, a.image, a.name, a.tries, a.allow))
    else:
        for o in ("tx", "cacert", "image", "tx_name"):
            if not getattr(a, o):
                die(f"--{o.replace('_', '-')} is required")
        sys.stdout.write(render_job(a.party, a.tx, a.cacert, a.image, a.tx_name))


if __name__ == "__main__":
    main()
