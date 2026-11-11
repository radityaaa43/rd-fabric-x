#!/usr/bin/env python3
"""Print the fx-gw-<N> gateway of one org for its own namespace (fabricx PLAN S16; stdout only, nothing is applied, no cluster, no key read).

usage: render.py bi|bank-a|bank-b|bank-c --templates <live dir with <node>/client-config.yaml (+ issuer-identity.bin for bi)>
                 --image repo@sha256:HEX (rdbi-node: fxapi) --envoy-image repo@sha256:HEX --opa-image repo@sha256:HEX
                 --tls-exchange DIR (org1..org4/msp/tlscacerts/*.pem: ONE root CA per org, public) --opa-config FILE (opa.yaml + the PUBLIC `keys:` block, ~/.opa-keys/opa-config.yaml) --gw-cert FILE (public cert of identity <node>-gw)
                 --gw-ips FILE ({cluster1:{N: addr}, cluster2:{N: addr}}: address of each gateway for peers in the OTHER cluster)
                 [--lb-acl acl-ID --lb-range <ipv4>/32 ...] [--public-params FILE (bi only: for the one-off `rdbi-driver setup-pp`)]
Objects: ConfigMaps fx-gw-<N>-envoy, fx-gw-<N>-opa, fx-gw-<N>-client (client-config.yaml of the gateway's node, gateway cert, issuer-identity.bin for bi only),
Services fx-gw-<N> (ClusterIP 8443), fx-gw-<N>-ext (NodePort, eTP Cluster, cluster-1 parties only: the Lensa path, like zeto bank-gw-<N>-ext) and one ExternalName `fx-gw-<M>` per same-cluster peer (the driver dials https://fx-gw-<M>:8443/, serve.go:43), NetworkPolicy fx-gw-<N> (ingress 8443 from any source, like zeto bank-gw-ingress: mTLS + OPA are the control),
Deployment fx-gw-<N> (envoy :8443 mTLS + ext_authz to OPA 127.0.0.1:9191, OPA bundles from the SAME party's zeto bundle-server read side only, fxapi `rdbi-driver serve <node>`).
hostAliases carry the cross-cluster peers. The LoadBalancer Service fx-gw-<N>-lb exists only with --lb-acl (existing ACL id, /32 ranges only).
NOT rendered, custody step (multiorg/gw/make_secrets.py): Secrets fx-gw-<N>-server (tls.crt, tls.key from the org's own TLS CA), fx-gw-<N>-client-ca (ca.crt: bank-gw-ca-<N> + the 4 TLS CAs, public),
fx-gw-<N>-peer (tls.crt, tls.key of identity fx-gw-<N>-peer), fx-gw-<N>-client (gw.key of identity <node>-gw).
ConfigMap fx-gw-<N>-peer-ca holds ca-1.crt..ca-4.crt (one public root per org): fxapi trusts, per peer gateway, ONLY that org's root (D4, driver peerFor).
"""
import argparse, base64, glob, os, re, sys
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))

PARTY_N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
NODE = {"bi": "issuer", "bank-a": "bank2", "bank-b": "bank3", "bank-c": "bank4"}
CLUSTER = {"bi": "cluster1", "bank-a": "cluster1", "bank-b": "cluster1", "bank-c": "cluster2"}
UID = 10001
HOME = "/home/rdbi"
T = f"{HOME}/.fabricx-token"
A = "service.beta.kubernetes.io/alibaba-cloud-loadbalancer-"
LABELS = {"app.kubernetes.io/part-of": "rd-fabricx"}
HOST32 = r"\d+\.\d+\.\d+\.\d+/32"
SEC = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}, "runAsNonRoot": True, "runAsUser": UID}


def die(msg):
    sys.exit(f"render.py: {msg}")


def typed(t, **kw):
    return {"@type": "type.googleapis.com/envoy.extensions." + t, **kw}


def envoy_config(n):
    """One door :8443, client certificate required. Envoy hands the verified client cert and subject to OPA (XFCC, SANITIZE_SET), so the rego can bind an identity to its issuing CA."""
    authz = typed("filters.http.ext_authz.v3.ExtAuthz", transport_api_version="V3", with_request_body={"max_request_bytes": 65536, "allow_partial_message": False},
                  failure_mode_allow=False, grpc_service={"envoy_grpc": {"cluster_name": "opa"}, "timeout": "3s"})
    hcm = typed("filters.network.http_connection_manager.v3.HttpConnectionManager", stat_prefix="fabricx",
                forward_client_cert_details="SANITIZE_SET", set_current_client_cert_details={"cert": True, "subject": True},
                route_config={"virtual_hosts": [{"name": "fxapi", "domains": ["*"], "routes": [{
                    "match": {"prefix": "/"},
                    "route": {"cluster": "fxapi", "timeout": "300s"},   # a transaction waits for finality (90s) and the report to BI
                    "typed_per_filter_config": {"envoy.filters.http.ext_authz": typed(
                        "filters.http.ext_authz.v3.ExtAuthzPerRoute", check_settings={"context_extensions": {"target": "fabricx", "node": f"node{n}"}})}}]}]},
                http_filters=[{"name": "envoy.filters.http.ext_authz", "typed_config": authz},
                              {"name": "envoy.filters.http.router", "typed_config": typed("filters.http.router.v3.Router")}])
    tls = typed("transport_sockets.tls.v3.DownstreamTlsContext", require_client_certificate=True, common_tls_context={
        "tls_params": {"tls_minimum_protocol_version": "TLSv1_2"},
        "tls_certificates": [{"certificate_chain": {"filename": "/mtls/tls.crt"}, "private_key": {"filename": "/mtls/tls.key"}}],
        "validation_context": {"trusted_ca": {"filename": "/client-ca/ca.crt"}}})

    def local(name, port, h2=False):
        c = {"name": name, "type": "STATIC", "connect_timeout": "1s",
             "load_assignment": {"cluster_name": name, "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": port}}}}]}]}}
        if h2:
            c["typed_extension_protocol_options"] = {"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": typed(
                "upstreams.http.v3.HttpProtocolOptions", explicit_http_config={"http2_protocol_options": {}})}
        return c
    return {"static_resources": {
        "listeners": [{"name": "fabricx", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8443}},
                       "filter_chains": [{"transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": tls},
                                          "filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": hcm}]}]}],
        "clusters": [local("fxapi", 8080), local("opa", 9191, h2=True)]},
        "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}}}


def opa_config_for(path, party):
    """The party's opa-config.yaml for a gateway that only READS bundles: bundle-server of the same party (zeto), no sink service, no token, decisions and status to console."""
    raw = open(path).read()
    if "PRIVATE KEY" in raw:
        die(f"{path} holds private key material: the OPA config carries public keys only")
    cfg = yaml.safe_load(raw)
    if not cfg.get("keys"):
        die(f"{path} has no `keys:` block (the public keys of the bundle owners; opa/keys.sh)")
    # the Service port is 80 (Service bundle-server: bundles port=80 targetPort=8080, sink 8081); naming the pod port 8080 hangs the bundle request (S16 bank-b)
    cfg["services"] = {"bundle-server": {"url": f"http://bundle-server.rd-zeto-{party}.svc.cluster.local"}}
    cfg["decision_logs"] = {"console": True, **{k: v for k, v in cfg.get("decision_logs", {}).items() if k not in ("service", "console")}}
    cfg["status"] = {"console": True}
    return yaml.safe_dump(cfg, sort_keys=False)


def render(party, templates, image, envoy_image, opa_image, opa_config, gw_cert, gw_ips, tls_exchange, lb=None, public_params=None):
    if party not in PARTY_N:
        die(f"party {party!r} must be one of {', '.join(PARTY_N)}")
    for what, v in (("--image", image), ("--envoy-image", envoy_image), ("--opa-image", opa_image)):
        if not re.fullmatch(r".+@sha256:[0-9a-f]{64}", v or ""):
            die(f"{what} must be pinned by digest (repo@sha256:<64 hex>)")
    n, node, ns, cluster, name = PARTY_N[party], NODE[party], f"rd-fabricx-{party}", CLUSTER[party], f"fx-gw-{PARTY_N[party]}"
    pl = {"app.kubernetes.io/name": name}
    meta = lambda nm, extra=None: {"name": nm, "namespace": ns, "labels": {**LABELS, **(extra or {})}}

    cc = yaml.safe_load(open(f"{templates}/{node}/client-config.yaml"))
    grpc_port = int(cc["address"].rsplit(":", 1)[-1])
    cc["address"] = f"{node}:{grpc_port}"
    cc["tlsconfig"]["peercacertpath"] = f"{T}/live/{node}/tls-ca.crt"
    cc["signerconfig"]["identitypath"] = f"{T}/gw/{node}-gw.pem"
    cc["signerconfig"]["keypath"] = f"{T}/gw/{node}-gw.key"
    client = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"{name}-client"),
              "data": {"client-config.yaml": yaml.safe_dump(cc, sort_keys=False), f"{node}-gw.pem": open(gw_cert).read()}}
    live_items = [{"key": "client-config.yaml", "path": f"live/{node}/client-config.yaml"}, {"key": f"{node}-gw.pem", "path": f"gw/{node}-gw.pem"}]
    if party == "bi":
        ip = f"{templates}/issuer-identity.bin"
        if not os.path.isfile(ip):
            die(f"{ip} is missing: the issuer gateway ships the public issuer identity")
        client["binaryData"] = {"issuer-identity.bin": base64.b64encode(open(ip, "rb").read()).decode()}
        live_items.append({"key": "issuer-identity.bin", "path": "live/issuer-identity.bin"})
        if public_params:   # S14: `rdbi-driver setup-pp` reads $HOME/.fabricx-token/live/public-params.bin; public data, shipped only for the one-off call on BI's gateway
            if not os.path.isfile(public_params):
                die(f"--public-params {public_params} is not a file")
            client["binaryData"]["public-params.bin"] = base64.b64encode(open(public_params, "rb").read()).decode()
            live_items.append({"key": "public-params.bin", "path": "live/public-params.bin"})
    elif public_params:
        die("--public-params is for the BI gateway only (the issuer node installs the public parameters)")

    roots = {}   # D4: fxapi pins each peer gateway to ITS org's root, so /peer holds ca-<M>.crt per org (never a bundle)
    for m in (1, 2, 3, 4):
        files = sorted(glob.glob(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem"))
        if len(files) != 1:
            die(f"{tls_exchange}/org{m}/msp/tlscacerts/*.pem: want exactly one root CA file, found {len(files)}")
        pem = open(files[0]).read()
        if pem.count("BEGIN CERTIFICATE") != 1 or "PRIVATE KEY" in pem:
            die(f"{files[0]} must hold exactly one public certificate")
        roots[f"ca-{m}.crt"] = pem
    ips = yaml.safe_load(open(gw_ips)) or {}
    peers = {m: q for q, m in PARTY_N.items() if m != n}
    same = {m: q for m, q in peers.items() if CLUSTER[q] == cluster}
    cross = {m: q for m, q in peers.items() if CLUSTER[q] != cluster}
    aliases = []
    for m in sorted(cross):
        a = (ips.get(CLUSTER[cross[m]]) or {}).get(m)
        if not a:
            die(f"--gw-ips has no address for fx-gw-{m} ({CLUSTER[cross[m]]}): the cross-cluster peer cannot be resolved")
        aliases.append({"ip": a, "hostnames": [f"fx-gw-{m}"]})

    docs = [{"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"{name}-envoy"), "data": {"envoy.yaml": yaml.safe_dump(envoy_config(n), sort_keys=False)}},
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"{name}-opa"), "data": {"opa.yaml": opa_config_for(opa_config, party)}},
            client, {"apiVersion": "v1", "kind": "ConfigMap", "metadata": meta(f"{name}-peer-ca"), "data": roots}]

    def res(cpu, mem, lim):
        return {"requests": {"cpu": cpu, "memory": mem}, "limits": {"memory": lim}}
    ro = lambda nm, path: {"name": nm, "mountPath": path, "readOnly": True}
    containers = [
        {"name": "envoy", "image": envoy_image, "args": ["-c", "/config/envoy.yaml", "--log-level", "warn"], "ports": [{"name": "fxapi", "containerPort": 8443}],
         "readinessProbe": {"tcpSocket": {"port": 8443}, "periodSeconds": 5}, "resources": res("10m", "32Mi", "128Mi"), "securityContext": SEC,
         "volumeMounts": [ro("envoy", "/config"), ro("mtls", "/mtls"), ro("client-ca", "/client-ca")]},
        {"name": "opa", "image": opa_image,
         "args": ["run", "--server", "--addr=localhost:8181", "--diagnostic-addr=0.0.0.0:8282", "--authorization=basic", "--config-file=/config/opa.yaml", f"--set=labels.gateway={name}",
                  "--set=bundles.bi.resource=bi/latest.tar.gz", "--set=bundles.bank.resource=bank/latest.tar.gz", f"--set=bundles.bank.signing.keyid={party}"],
         "readinessProbe": {"httpGet": {"path": "/health?plugins&bundles", "port": 8282}, "periodSeconds": 5},
         "livenessProbe": {"httpGet": {"path": "/health", "port": 8282}, "periodSeconds": 10},
         "resources": res("20m", "64Mi", "256Mi"), "securityContext": SEC, "volumeMounts": [ro("opa", "/config")]},
        {"name": "fxapi", "image": image, "command": ["rdbi-driver", "serve", node, "127.0.0.1:8080"],
         "env": [{"name": "HOME", "value": HOME}, {"name": "FXGW_TLS", "value": "/peer"}, {"name": "RDBI_REDELIVER_INTERVAL", "value": "60s"}],
         # fxapi listens on 127.0.0.1 only (behind Envoy): a kubelet tcpSocket probe on the pod IP cannot reach it
         "readinessProbe": {"exec": {"command": ["bash", "-c", ": >/dev/tcp/127.0.0.1/8080"]}, "periodSeconds": 5},
         "resources": res("10m", "32Mi", "256Mi"), "securityContext": SEC,
         "volumeMounts": [{"name": "home", "mountPath": HOME}, ro("live", T), ro("peer", "/peer")]}]
    volumes = [{"name": "mtls", "secret": {"secretName": f"{name}-server", "defaultMode": 0o440}},
               {"name": "client-ca", "secret": {"secretName": f"{name}-client-ca", "defaultMode": 0o440}},
               {"name": "envoy", "configMap": {"name": f"{name}-envoy"}}, {"name": "opa", "configMap": {"name": f"{name}-opa"}},
               {"name": "home", "emptyDir": {}},
               {"name": "peer", "projected": {"defaultMode": 0o440, "sources": [
                   {"secret": {"name": f"{name}-peer", "items": [{"key": "tls.crt", "path": "tls.crt"}, {"key": "tls.key", "path": "tls.key"}]}},
                   {"configMap": {"name": f"{name}-peer-ca", "items": [{"key": k, "path": k} for k in sorted(roots)]}}]}},
               {"name": "live", "projected": {"defaultMode": 0o440, "sources": [
                   {"configMap": {"name": f"{name}-client", "items": live_items}},
                   {"secret": {"name": f"{name}-client", "items": [{"key": "gw.key", "path": f"gw/{node}-gw.key"}]}},
                   {"configMap": {"name": "rdbi-public", "items": [{"key": "ca-bundle.pem", "path": f"live/{node}/tls-ca.crt"}]}}]}}]
    spec = {"imagePullSecrets": [{"name": "ghcr-pull"}],   # rdbi-node-ci is a private package (the existing Secret ghcr-pull is in every org namespace)
            "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "fsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
            "containers": containers, "volumes": volumes}
    if aliases:
        spec["hostAliases"] = aliases
    docs.append({"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta(name, pl),
                 "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": pl}, "template": {"metadata": {"labels": {**LABELS, **pl}}, "spec": spec}}})
    docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta(name, pl),
                 "spec": {"selector": pl, "ports": [{"name": "fxapi", "port": 8443, "targetPort": 8443}]}})
    for m in sorted(same):
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta(f"fx-gw-{m}"),
                     "spec": {"type": "ExternalName", "externalName": f"fx-gw-{m}.rd-fabricx-{same[m]}.svc.cluster.local"}})

    if cluster == "cluster1":   # the Lensa path, mirror of zeto bank-gw-<N>-ext (NodePort eTP Cluster; the port is allocated by Kubernetes)
        docs.append({"apiVersion": "v1", "kind": "Service", "metadata": meta(f"{name}-ext", pl),
                     "spec": {"type": "NodePort", "externalTrafficPolicy": "Cluster", "selector": pl, "ports": [{"name": "fxapi", "port": 8443, "targetPort": 8443, "protocol": "TCP"}]}})
    if lb:
        acl, ranges = lb.get("acl_id"), lb.get("ranges") or []
        if not re.fullmatch(r"acl-[a-z0-9]+", acl or ""):
            die("--lb-acl must be an EXISTING access control list id (acl-...): no LB without an ACL")
        if not ranges or any(not re.fullmatch(HOST32, r) for r in ranges):
            die("--lb-range must be one or more <ipv4>/32 (nothing wider)")
        docs.append({"apiVersion": "v1", "kind": "Service",
                     "metadata": {**meta(f"{name}-lb", pl), "annotations": {A + "acl-status": "on", A + "acl-id": acl, A + "acl-type": "white", A + "address-type": "internet", A + "scheduler": "wrr",
                                                                         "service.beta.kubernetes.io/backend-type": "eni"}},
                     "spec": {"type": "LoadBalancer", "externalTrafficPolicy": "Cluster", "loadBalancerSourceRanges": ranges, "selector": pl,
                              "ports": [{"name": "fxapi", "port": 8443, "targetPort": 8443, "protocol": "TCP"}]}})
    docs.append({"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(name),
                 "spec": {"podSelector": {"matchLabels": pl}, "policyTypes": ["Ingress"], "ingress": [{"ports": [{"protocol": "TCP", "port": 8443}]}]}})
    return yaml.safe_dump_all(docs, sort_keys=False)



def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("party")
    for o in ("templates", "image", "envoy-image", "opa-image", "opa-config", "gw-cert", "gw-ips", "tls-exchange", "lb-acl"):
        ap.add_argument(f"--{o}")
    ap.add_argument("--lb-range", action="append", default=[])
    ap.add_argument("--public-params")
    a = ap.parse_args()
    for o in ("templates", "image", "envoy_image", "opa_image", "opa_config", "gw_cert", "gw_ips", "tls_exchange"):
        if not getattr(a, o):
            die(f"--{o.replace('_', '-')} is required")
    lb = {"acl_id": a.lb_acl, "ranges": a.lb_range} if a.lb_acl else None
    sys.stdout.write(render(a.party, a.templates, a.image, a.envoy_image, a.opa_image, a.opa_config, a.gw_cert, a.gw_ips, a.tls_exchange, lb, a.public_params))


if __name__ == "__main__":
    main()
