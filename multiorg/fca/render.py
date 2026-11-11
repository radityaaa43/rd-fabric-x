#!/usr/bin/env python3
"""Print the fabric-ca manifests of one party's own CA `fca-org<N>` (fabricx S9; stdout only, no cluster).

usage: render.py bi|bank-a|bank-b [--zone Z] [--storage-class SC]   (defaults ap-southeast-5b, alicloud-essd-wffc)
       render.py bank-c --zone Z --storage-class SC               (cluster 2: both required; zone = most free attach slots from the PRE)
       pipe to `kubectl --kubeconfig <party kubeconfig> apply -f -` inside a GO window
Service + PVC (CA home: CA key, cert, sqlite registry) + Deployment, restricted-PSS, image by digest. No Secret here:
the admin password Secret `fca-org<N>-admin` is created by enroll.py. bank-c lands on cluster 2: use its own kubeconfig.
"""
import re, sys
import yaml

N = {"bi": 1, "bank-a": 2, "bank-b": 3, "bank-c": 4}
IMAGE = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"  # 1.5.22, as running today
PORT = 7054
DEFAULT_SC = "alicloud-essd-wffc"  # cluster 1 (as k8s.py)
DEFAULT_ZONE = "ap-southeast-5b"  # as panurus-itest/scripts/k8s.py: the cluster-1 nodes with free disk slots


def render(party, zone=None, storage_class=None):
    if party not in N:
        sys.exit(f"render.py: party {party!r} unknown; use one of {', '.join(N)}")
    if zone is None and party == "bank-c":
        sys.exit("render.py: bank-c needs --zone <z> (cluster 2: the zone with the most free disk-attach slots, from the PRE)")
    if storage_class is None and party == "bank-c":
        sys.exit("render.py: bank-c needs --storage-class <sc> (cluster 2 has no alicloud-essd-wffc; name one that exists there)")
    storage_class = DEFAULT_SC if storage_class is None else storage_class
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", storage_class):
        sys.exit(f"render.py: storage class {storage_class!r} is not a name")
    zone = DEFAULT_ZONE if zone is None else zone
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", zone):
        sys.exit(f"render.py: zone {zone!r} is not a zone name")
    n, ns, name = N[party], f"rd-fabricx-{party}", f"fca-org{N[party]}"
    labels = {"app.kubernetes.io/part-of": "rd-fabricx", "app.kubernetes.io/name": name, "party": party}
    meta = lambda nm: {"name": nm, "namespace": ns, "labels": labels}
    env = [{"name": "FABRIC_CA_SERVER_HOME", "value": "/data"},
           {"name": "FABRIC_CA_SERVER_CA_NAME", "value": name},
           {"name": "FABRIC_CA_SERVER_PORT", "value": str(PORT)},
           {"name": "FABRIC_CA_SERVER_CSR_CN", "value": name},
           {"name": "FABRIC_CA_SERVER_CSR_HOSTS", "value": f"{name},{name}.{ns}.svc,{name}.{ns}.svc.cluster.local,localhost"},
           {"name": "ADMIN_PASS", "valueFrom": {"secretKeyRef": {"name": f"{name}-admin", "key": "password"}}}]
    docs = [
        {"apiVersion": "v1", "kind": "Service", "metadata": meta(name),
         "spec": {"selector": {"app.kubernetes.io/name": name}, "ports": [{"name": "api", "port": PORT, "targetPort": PORT}]}},
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": meta(f"{name}-data"),
         "spec": {"accessModes": ["ReadWriteOnce"], "storageClassName": storage_class,
                  "resources": {"requests": {"storage": "2Gi"}}}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta(name),
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": {"app.kubernetes.io/name": name}},
                  "template": {"metadata": {"labels": labels}, "spec": {
                      "securityContext": {"runAsNonRoot": True, "runAsUser": 10001, "seccompProfile": {"type": "RuntimeDefault"}, "fsGroup": 10001},
                      "nodeSelector": {"topology.kubernetes.io/zone": zone},
                      # one CA per node: required anti-affinity against the other parties' CA pods, across namespaces
                      "affinity": {"podAntiAffinity": {"requiredDuringSchedulingIgnoredDuringExecution": [{
                          "topologyKey": "kubernetes.io/hostname", "namespaceSelector": {},
                          "labelSelector": {"matchExpressions": [
                              {"key": "app.kubernetes.io/name", "operator": "In", "values": [f"fca-org{m}" for m in N.values()]},
                              {"key": "app.kubernetes.io/name", "operator": "NotIn", "values": [name]}]}}]}},  # WaitForFirstConsumer: the disk binds to the first pod's zone
                      "containers": [{
                          "name": "fabric-ca", "image": IMAGE, "command": ["sh", "-c", "fabric-ca-server start -b admin:$ADMIN_PASS --tls.enabled=false"],
                          "env": env, "ports": [{"name": "api", "containerPort": PORT}],
                          "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                          "readinessProbe": {"tcpSocket": {"port": PORT}, "periodSeconds": 5},
                          "resources": {"requests": {"cpu": "20m", "memory": "64Mi", "ephemeral-storage": "64Mi"},
                                        "limits": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "512Mi"}},
                          "volumeMounts": [{"name": "data", "mountPath": "/data"}]}],
                      "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}}]}}}},
    ]
    return yaml.safe_dump_all(docs, sort_keys=False)


if __name__ == "__main__":
    a, opt = sys.argv[1:], {}
    while len(a) >= 3 and a[-2] in ("--zone", "--storage-class"):
        opt[a[-2]], a = a[-1], a[:-2]
    if len(a) != 1:
        sys.exit(__doc__)
    sys.stdout.write(render(a[0], opt.get("--zone"), opt.get("--storage-class")))
