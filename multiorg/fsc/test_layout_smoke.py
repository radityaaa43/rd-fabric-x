"""Layout smoke for multiorg/fsc/render.py (fabricx S13 piece 4): apply the rendered volume items the way the pod's `layout` init container does (items + paths, then the cp
into $T) and check that EVERY path each node's rendered core.yaml names exists in that tree. It proves file layout only: the node itself (rdbi-node image) starts only on the
cluster, so P2P, MSP loading and orderer reachability are NOT covered (RUNBOOK-S13 UNVERIFIED).

  python3 -m unittest discover -s multiorg/fsc
"""
import os, sys, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import enroll_fsc
import test_render as tr
import test_core_rewrite as tcr


def strings(o):
    if isinstance(o, dict):
        for v in o.values():
            yield from strings(v)
    elif isinstance(o, list):
        for v in o:
            yield from strings(v)
    elif isinstance(o, str):
        yield o


class Layout(tr.Base):
    def tree(self, party):
        docs = self.r(party)
        cms, dep = self.by(docs, "ConfigMap"), next(d for d in docs if d["kind"] == "Deployment")
        spec = dep["spec"]["template"]["spec"]
        vol = {v["name"]: v for v in spec["volumes"]}
        pod = tr.POD[party]
        n = tr.PARTIES[party]
        nodes = enroll_fsc.NODES[party][1]
        # what the cluster would hold: the Secret made by enroll_fsc (+ central import), the existing endorser Secret, arma-public
        secret = {enroll_fsc.secret_key(f"own/{x}/{rel}"): "own" for x in nodes for rel in enroll_fsc.own_files(x)}
        secret.update({k: "central" for x in nodes for k in tr.CENTRAL.get(x, [])})
        ext = {f"rdbi-{pod}-files": secret, f"fsc-endorser-{n}-secret": {"msp-keystore-priv_sk": "k", "msp-signcert.pem": "c"}}
        tree = set()
        own = vol["own"]["projected"]["sources"]
        for s in own:
            if "secret" in s:
                for i in s["secret"]["items"]:
                    self.assertIn(i["key"], ext[s["secret"]["name"]], f"{s['secret']['name']} lacks {i['key']}")
                    tree.add(f"own/{i['path']}")
            else:
                cm = cms.get(s["configMap"]["name"], {"data": {"msp-cacert.pem": "x"}})["data"]   # arma-public-<N> is made by the arma render
                for i in s["configMap"]["items"]:
                    self.assertIn(i["key"], cm)
                    tree.add(f"own/{i['path']}")
        for i in vol["public"]["configMap"]["items"]:
            self.assertIn(i["key"], cms["rdbi-public"]["data"])
            tree.add(f"public/{i['path']}")
        for x in nodes:
            tree.add(f"live/{x}/core.yaml")
        return tree, [yaml.safe_load(cms[f"rdbi-core-{x}"]["data"]["core.yaml"]) for x in nodes], nodes

    def exists(self, tree, rel):
        return rel in tree or any(t.startswith(rel + "/") for t in tree)

    def test_every_path_in_every_core_exists_after_the_layout_init(self):
        for party in tr.PARTIES:
            tree, cores, nodes = self.tree(party)
            for node, core in zip(nodes, cores):
                for s in strings(core):
                    if not s.startswith(tcr.T + "/"):
                        continue
                    rel = s[len(tcr.T) + 1:]
                    if rel.startswith(f"live/{node}/data") or rel == f"live/{node}/trace.out":
                        continue   # the PVC and the node's own output
                    self.assertTrue(self.exists(tree, rel), f"{party}/{node}: {s} is not in the pod after the layout init")

    def test_no_other_nodes_private_file_is_in_the_pod(self):
        for party in tr.PARTIES:
            tree, _, nodes = self.tree(party)
            for t in tree:
                if t.startswith("own/"):
                    self.assertIn(t.split("/")[1], nodes, t)


if __name__ == "__main__":
    unittest.main()
