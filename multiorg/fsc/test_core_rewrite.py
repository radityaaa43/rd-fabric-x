"""Offline tests for multiorg/fsc/core_rewrite.py (fabricx S13 piece 1: the per-org core.yaml of an FSC node).
The fixture has the shape of the NWO-generated core.yaml of panurus-itest (paths and keys as read from ~/.fabricx-token/live/<node>/core.yaml, values synthetic).

  python3 -m unittest discover -s multiorg/fsc
"""
import copy, os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import core_rewrite as cr

H = "/home/ecs-user/.fabricx-token"
T = "/home/rdbi/.fabricx-token"
NODES = ["issuer", "bank2", "bank3", "bank4", "endorser-1", "endorser-2", "endorser-3", "endorser-4"]
GRPC = {n: 5100 + 3 * i for i, n in enumerate(NODES)}
MSP_OLD = {"issuer": "Org1MSP", "bank2": "OrdererOrg2MSP", "bank3": "OrdererOrg3MSP", "bank4": "OrdererOrg4MSP",
           "endorser-1": "Org1MSP", "endorser-2": "OrdererOrg2MSP", "endorser-3": "OrdererOrg3MSP", "endorser-4": "OrdererOrg4MSP"}
FSC = f"{H}/livegen/fsc/crypto/peerOrganizations/fsc.example.com"


def core(node):
    bank = node.startswith("bank") or node == "issuer"
    own = f"{FSC}/peers/{node}.fsc.example.com"
    res = [{"name": n, "domain": "fsc.example.com", "identity": {"path": f"{FSC}/peers/{n}.fsc.example.com/msp/signcerts/{n}.fsc.example.com-cert.pem"},
            "addresses": {"P2P": f"127.0.0.1:{GRPC[n] + 1}"}} for n in NODES]
    res.append({"name": "lib-p2p-bootstrap-node", "domain": "fsc.example.com", "addresses": {"P2P": "127.0.0.1:5125"},
                "identity": {"path": f"{FSC}/peers/lib-p2p-bootstrap-node.fsc.example.com/msp/signcerts/lib-p2p-bootstrap-node.fsc.example.com-cert.pem"}})
    fres = [{"name": n, "domain": f"org{i + 1}.example.com", "identity": {"mspID": MSP_OLD[n], "path": f"{H}/ids/{n}/msp"}, "addresses": None}
            for i, n in enumerate(NODES) if n != node]
    msps = [{"id": node, "mspID": MSP_OLD[node], "mspType": "bccsp", "path": f"{H}/ids/{node}/msp"}]
    if node.startswith("bank") or node == "issuer":
        msps.insert(0, {"id": "idemix", "mspID": "IdemixOrgMSP", "mspType": "idemix", "path": f"{H}/ids/anon/msp"})
    tls = {"enabled": True, "clientAuthEnabled": True, "clientCert": {"file": f"{H}/ids/{node}/tls/signcerts/cert.pem"},
           "clientKey": {"file": f"{H}/ids/{node}/tls/keystore/abc123_sk"}, "rootCAs": {"files": [f"{H}/live/ca-bundle.pem"]}}
    d = {"fsc": {"id": node, "identity": {"cert": {"file": f"{own}/msp/signcerts/{node}.fsc.example.com-cert.pem"}, "key": {"file": f"{own}/msp/keystore/priv_sk"}},
                 "client": {"certs": [f"{FSC}/users/Admin@fsc.example.com/msp/signcerts/Admin@fsc.example.com-cert.pem"]},
                 "tls": {"enabled": True, "cert": {"file": f"{own}/tls/server.crt"}, "key": {"file": f"{own}/tls/server.key"}},
                 "grpc": {"enabled": True, "address": f"127.0.0.1:{GRPC[node]}"},
                 "p2p": {"type": "websocket", "listenAddress": f"/ip4/0.0.0.0/tcp/{GRPC[node] + 1}"},
                 "web": {"enabled": False, "address": f"0.0.0.0:{GRPC[node] + 2}", "tls": {"clientRootCAs": {"files": [f"{own}/tls/ca.crt"]}}},
                 "persistences": {"default": {"opts": {"dataSource": f"{H}/live/{node}/data/default.sqlite"}}},
                 "tracing": {"file": {"path": f"{H}/live/{node}/trace.out"}},
                 "endpoint": {"resolvers": res}},
         "fabric": {"default": {"defaultMSP": node, "msps": msps, "endpoint": {"resolvers": fres}, "tls": tls,
                                "peers": [{"address": "172.24.11.197:30560"}],
                                "notificationService": {"endpoints": [{"address": "172.24.11.197:30560", "tls": copy.deepcopy(tls)}]},
                                "queryService": {"endpoints": [{"address": "172.24.11.197:30580", "tls": copy.deepcopy(tls)}]}}},
         "token": {"tms": {"default-arma-rd_dfabi_v2": {"namespace": "rd_dfabi_v2"}}}}
    if node.startswith("bank"):
        d["token"]["tms"]["default-arma-rd_dfabi_v2"]["wallets"] = {"owners": [{"id": node, "path": f"{H}/livegen/token/crypto/default-testchannel-token_chaincode/idemix/{node}"}]}
    if node == "issuer":   # the token issuer wallet MSP (private), only the issuer node has it
        d["token"]["tms"]["default-arma-rd_dfabi_v2"]["wallets"] = {"issuers": [{"id": "issuer", "path": f"{H}/livegen/token/crypto/default-testchannel-token_chaincode/issuer/issuers/peerOrganizations/Orgissuer.example.com/users/issuer@Orgissuer.example.com/msp"}]}
    return d


def strings(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from strings(v, f"{path}.{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from strings(v, f"{path}[{i}]")
    elif isinstance(o, str):
        yield path, o


def get(o, dotted):
    for part in dotted.split("."):
        o = o[int(part)] if isinstance(o, list) else o[part]
    return o


class Rewrite(unittest.TestCase):
    def run_node(self, node):
        c = core(node)
        orig = copy.deepcopy(c)
        out, manifest = cr.per_org_core(c, node, H, T)
        self.assertEqual(c, orig)   # the template is not modified
        return out, manifest

    def test_no_host_path_survives_and_nothing_points_at_the_shared_namespace(self):
        for n in NODES:
            out, _ = self.run_node(n)
            for p, v in strings(out):
                self.assertNotIn("/home/ecs-user", v, f"{n} {p}")
                self.assertNotIn("livegen", v, f"{n} {p}")
                self.assertNotIn("fabricx.svc", v, f"{n} {p}")
                self.assertNotIn("172.24.", v, f"{n} {p}")

    def test_own_keys_under_own_and_foreign_nodes_only_public(self):
        for n in NODES:
            out, man = self.run_node(n)
            secret = {k: v for k, v in man.items() if v["kind"] == "secret"}
            for pod, info in secret.items():
                self.assertTrue(pod.startswith(f"{T}/own/{n}/"), pod)   # issuer and endorser-1 share one pod: private files are per node
                self.assertNotIn("/".join(["", "ids", ""]) + "bank9", info["src"])
            foreign = [m for m in NODES if m != n]
            for pod, info in man.items():
                for m in foreign:
                    if f"/{m}/" in info["src"] or f"/{m}.fsc" in info["src"]:
                        self.assertEqual(info["kind"], "public", f"{n} holds a foreign non-public file {info['src']}")
                        self.assertTrue(pod.startswith(f"{T}/public/"), pod)

    def test_manifest_secret_keys_are_exactly_the_own_private_keys(self):
        out, man = self.run_node("bank2")
        keys = sorted(v["src"].replace(H, "$H") for v in man.values() if v["kind"] == "secret")
        self.assertEqual(keys, ["$H/ids/anon/msp", "$H/ids/bank2/msp", "$H/ids/bank2/tls/keystore/abc123_sk",
                                "$H/livegen/fsc/crypto/peerOrganizations/fsc.example.com/peers/bank2.fsc.example.com/msp/keystore/priv_sk",
                                "$H/livegen/fsc/crypto/peerOrganizations/fsc.example.com/peers/bank2.fsc.example.com/tls/server.key",
                                "$H/livegen/token/crypto/default-testchannel-token_chaincode/idemix/bank2"])
        _, man = self.run_node("endorser-3")
        keys = sorted(v["src"].replace(H, "$H") for v in man.values() if v["kind"] == "secret")
        self.assertEqual(keys, ["$H/ids/endorser-3/msp", "$H/ids/endorser-3/tls/keystore/abc123_sk",
                                "$H/livegen/fsc/crypto/peerOrganizations/fsc.example.com/peers/endorser-3.fsc.example.com/msp/keystore/priv_sk",
                                "$H/livegen/fsc/crypto/peerOrganizations/fsc.example.com/peers/endorser-3.fsc.example.com/tls/server.key"])

    def test_issuer_wallet_msp_is_private_and_issuer_only(self):
        out, man = self.run_node("issuer")
        w = [v for v in man.values() if "issuers/peerOrganizations" in v["src"]]
        self.assertEqual([v["kind"] for v in w], ["secret"])
        pod = next(k for k, v in man.items() if "issuers/peerOrganizations" in v["src"])
        self.assertTrue(pod.startswith(f"{T}/own/issuer/wallets/"), pod)
        c = core("bank2")
        c["token"]["tms"]["default-arma-rd_dfabi_v2"]["wallets"]["issuers"] = core("issuer")["token"]["tms"]["default-arma-rd_dfabi_v2"]["wallets"]["issuers"]
        with self.assertRaises(ValueError):   # a bank must never carry the issuer wallet
            cr.per_org_core(c, "bank2", H, T)

    def test_view_api_client_cert_is_the_nodes_own_admin_cert_not_the_central_one(self):
        for n in NODES:
            out, man = self.run_node(n)
            self.assertEqual(out["fsc"]["client"]["certs"], [f"{T}/own/{n}/fsc/admin.pem"])
            self.assertEqual(man[f"{T}/own/{n}/fsc/admin.pem"]["kind"], "public")
            self.assertNotIn(f"{T}/public/fsc/admin.pem", man)

    def test_own_committer_endpoints(self):
        for n in NODES:
            out, _ = self.run_node(n)
            d = out["fabric"]["default"]
            self.assertEqual(d["peers"][0]["address"], "committer-sidecar:5130")
            self.assertEqual(d["notificationService"]["endpoints"][0]["address"], "committer-sidecar:5130")
            self.assertEqual(d["queryService"]["endpoints"][0]["address"], "committer-query-service:5140")

    def test_p2p_names_keep_ports_and_view_api_listens_on_all_addresses(self):
        out, _ = self.run_node("bank3")
        self.assertEqual(out["fsc"]["grpc"]["address"], f"0.0.0.0:{GRPC['bank3']}")
        by = {r["name"]: r for r in out["fsc"]["endpoint"]["resolvers"]}
        for n in NODES:
            self.assertEqual(by[n]["addresses"]["P2P"], f"{n}:{GRPC[n] + 1}")
        self.assertEqual(by["lib-p2p-bootstrap-node"]["addresses"]["P2P"], "127.0.0.1:5125")   # pod-local bootstrap, untouched

    def test_msp_ids_are_the_genesis_org_names(self):
        for n in NODES:
            out, _ = self.run_node(n)
            d = out["fabric"]["default"]
            ids = {m["mspType"]: m["mspID"] for m in d["msps"]}
            self.assertEqual(ids["bccsp"], f"org{(NODES.index(n) % 4) + 1}")
            if "idemix" in ids:
                self.assertEqual(ids["idemix"], "IdemixOrgMSP")   # untouched until S15
            for r in d["endpoint"]["resolvers"]:
                self.assertRegex(r["identity"]["mspID"], r"^org[1-4]$")

    def test_state_paths_keep_the_pvc_layout(self):
        out, man = self.run_node("endorser-2")
        self.assertEqual(out["fsc"]["persistences"]["default"]["opts"]["dataSource"], f"{T}/live/endorser-2/data/default.sqlite")
        self.assertEqual(out["fsc"]["tracing"]["file"]["path"], f"{T}/live/endorser-2/trace.out")
        self.assertEqual(man[f"{T}/live/endorser-2/data/default.sqlite"]["kind"], "state")

    def test_unknown_host_path_is_refused(self):
        c = core("bank2")
        c["fsc"]["extra"] = {"file": f"{H}/somewhere/else.pem"}
        with self.assertRaises(ValueError):
            cr.per_org_core(c, "bank2", H, T)

    def test_foreign_secret_path_in_a_resolver_is_refused(self):
        c = core("bank2")
        c["fabric"]["default"]["endpoint"]["resolvers"][0]["identity"]["path"] = f"{H}/ids/bank3/tls/keystore/x_sk"
        with self.assertRaises(ValueError):
            cr.per_org_core(c, "bank2", H, T)


if __name__ == "__main__":
    unittest.main()
