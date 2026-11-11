#!/usr/bin/env python3
"""Pull-test Deployment `pull-test-fx` DERIVED from the real gateway Deployment (S16 step 0): same imagePullSecrets, ServiceAccount and securityContext, every gateway image once,
imagePullPolicy Always (a node-cached image must not hide a missing pull secret: live S16 bank-a ImagePullBackOff 401 while bank-b/bi passed through the cache).

usage: pulltest.py <party> <replicas 0|1> <same render inputs as render.py>   (prints the Deployment; nothing is applied)
The gateway containers are run once for their version: envoy `--version`, opa `version` as initContainers; the rdbi-node-ci container sleeps as the main container."""
import importlib.util, os, sys, copy
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("gw_render", os.path.join(HERE, "render.py"))
gw = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gw)

PODLEVEL = ("imagePullSecrets", "serviceAccountName", "securityContext", "hostAliases", "nodeSelector", "automountServiceAccountToken")


def render_pulltest(gw_deployment, replicas):
    spec = gw_deployment["spec"]["template"]["spec"]
    if not spec.get("imagePullSecrets"):
        sys.exit("pulltest.py: the gateway Deployment has no imagePullSecrets: the private image cannot be pulled (a node cache would hide it)")
    ns = gw_deployment["metadata"]["namespace"]
    labels = {"app.kubernetes.io/name": "pull-test-fx", "app.kubernetes.io/part-of": "rd-fabricx"}
    res = {"requests": {"cpu": "5m", "memory": "16Mi", "ephemeral-storage": "8Mi"}, "limits": {"cpu": "200m", "memory": "128Mi", "ephemeral-storage": "16Mi"}}
    init, main = [], None
    for c in spec["containers"]:
        base = {"name": c["name"], "image": c["image"], "imagePullPolicy": "Always", "securityContext": copy.deepcopy(c["securityContext"]), "resources": res}
        if c["name"] == "envoy":
            init.append({**base, "args": ["--version"]})
        elif c["name"] == "opa":
            init.append({**base, "args": ["version"]})
        else:
            main = {**base, "command": ["sleep", "infinity"]}
    pod = {k: copy.deepcopy(spec[k]) for k in PODLEVEL if k in spec}
    pod.update({"initContainers": init, "containers": [main]})
    d = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "pull-test-fx", "namespace": ns, "labels": labels},
         "spec": {"replicas": replicas, "selector": {"matchLabels": {"app.kubernetes.io/name": "pull-test-fx"}}, "template": {"metadata": {"labels": labels}, "spec": pod}}}
    return yaml.safe_dump(d, sort_keys=False)


if __name__ == "__main__":
    party, replicas, rest = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
    import subprocess
    out = subprocess.run([sys.executable, "-I", os.path.join(HERE, "render.py"), party, *rest], capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stderr)
    dep = [d for d in yaml.safe_load_all(out.stdout) if d and d["kind"] == "Deployment"][0]
    sys.stdout.write(render_pulltest(dep, replicas))
