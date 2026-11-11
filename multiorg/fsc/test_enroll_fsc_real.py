"""enroll_fsc.py against the REAL pinned fabric-ca server (docker, throwaway, localhost) and the REAL fabric-ca-client. Only kubectl is stubbed (it captures the Secret manifest).
Why: the stub-client tests only assert argv, so a cert whose SAN is the enrolling host's hostname (live S13: every p2p listener served SAN `bi-server`) passed offline.
The FSC websocket p2p listener serves the node's IDENTITY cert (fsc/cert.pem, the msp enrolment), not fsc/tls.crt (proved live 2026-11-11 21:29Z: presented fingerprints == fsc-exchange fsc/<node>.pem).
So the identity cert must carry the names peers dial. Also the contract of the in-namespace re-issue Job: `fabric-ca-client reenroll` with the CURRENT identity cert+key only (no CA admin password).

  REQUIRE_REAL_CA=1 python3 -m unittest multiorg.fsc.test_enroll_fsc_real     (CI sets it: missing docker/client is then a failure, not a skip)
"""
import base64, glob, hashlib, json, os, shutil, socket, subprocess, sys, tempfile, time, unittest
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "fca"))
sys.path.insert(0, HERE)
IMG = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"
NAMES = "C=US,ST=North Carolina,O=Hyperledger"


def have():
    return shutil.which("docker") and shutil.which("fabric-ca-client")


def san(pem):
    r = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=pem, capture_output=True, text=True)
    return sorted(x.strip()[4:] for line in r.stdout.splitlines() if "DNS:" in line for x in line.split(","))


def subject(pem):
    return subprocess.run(["openssl", "x509", "-noout", "-subject"], input=pem, capture_output=True, text=True).stdout.strip()


def pubkey_fp(pem, kind):
    a = ["openssl", "x509", "-noout", "-pubkey"] if kind == "cert" else ["openssl", "pkey", "-pubout"]
    return hashlib.sha256(subprocess.run(a, input=pem, capture_output=True, text=True).stdout.encode()).hexdigest()


@unittest.skipUnless(have() or os.environ.get("REQUIRE_REAL_CA"), "docker and fabric-ca-client needed (CI sets REQUIRE_REAL_CA=1)")
class RealCA(unittest.TestCase):
    PARTY, NS, N, NODES = "bank-b", "rd-fabricx-bank-b", 3, ["bank3", "endorser-3"]

    @classmethod
    def setUpClass(cls):
        if not have():
            raise AssertionError("REQUIRE_REAL_CA=1 but docker or fabric-ca-client is missing")
        import enroll_fsc
        os.umask(0o077)
        cls.W = tempfile.mkdtemp(prefix="realenr.", dir="/dev/shm")
        cls.T = tempfile.mkdtemp(prefix="realenr-pub.")
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()
        cls.cid = subprocess.run(["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{cls.port}:7054", IMG, "fabric-ca-server", "start", "-b", "admin:pw", "--tls.enabled=false"],
                                 capture_output=True, text=True, check=True).stdout.strip()
        for _ in range(120):
            if subprocess.run(["curl", "-sf", f"http://127.0.0.1:{cls.port}/cainfo"], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("fabric-ca-server did not come up")
        ex = f"{cls.T}/ex/org{cls.N}/msp"
        os.makedirs(f"{ex}/cacerts")
        os.makedirs(f"{ex}/knowncerts")
        ca = subprocess.run(["curl", "-s", f"http://127.0.0.1:{cls.port}/cainfo"], capture_output=True, text=True).stdout
        with open(f"{ex}/cacerts/ca.pem", "wb") as f:
            f.write(base64.b64decode(json.loads(ca)["result"]["CAChain"]))
        shutil.copy(f"{ex}/cacerts/ca.pem", f"{ex}/knowncerts/endorser-{cls.N}-cert.pem")
        with open(f"{cls.W}/admin.pass", "w") as f:
            f.write("pw")
        os.makedirs(f"{cls.T}/bin")
        with open(f"{cls.T}/bin/kubectl", "w") as f:
            f.write(f"#!/bin/sh\ncat > {cls.T}/secret.yaml\n")
        os.chmod(f"{cls.T}/bin/kubectl", 0o755)
        cls.path = os.environ["PATH"]
        os.environ["PATH"] = f"{cls.T}/bin:{cls.path}"
        enroll_fsc.make(cls.PARTY, cls.NS, "/nonexistent", f"http://127.0.0.1:{cls.port}", cls.W, f"{cls.T}/ex", f"{cls.T}/out/org{cls.N}")
        cls.sec = yaml.safe_load(open(f"{cls.T}/secret.yaml"))["stringData"]

    @classmethod
    def tearDownClass(cls):
        os.environ["PATH"] = cls.path
        subprocess.run(["docker", "stop", cls.cid], capture_output=True)
        shutil.rmtree(cls.T, ignore_errors=True)
        shutil.rmtree(cls.W, ignore_errors=True)

    def want(self, node):
        return sorted([node, f"{node}.{self.NS}.svc.cluster.local"])

    def test_tls_pair_carries_the_node_names(self):
        for node in self.NODES:
            self.assertEqual(san(self.sec[f"own__{node}__fsc__tls.crt"]), self.want(node), node)

    def test_identity_cert_carries_the_node_names(self):
        """RED before the fix: the msp enrolment had no --csr.hosts, so the SAN was the enrolling host's hostname"""
        for node in self.NODES:
            self.assertEqual(san(self.sec[f"own__{node}__fsc__cert.pem"]), self.want(node), node)

    def reenroll(self, node, profile=""):
        """what the in-namespace Job runs: the CURRENT identity cert+key only, no CA admin password, no FABRIC_CA_CLIENT_URL credentials"""
        out = tempfile.mkdtemp(prefix=f"re-{node}.", dir=self.T)
        os.makedirs(f"{out}/signcerts")
        os.makedirs(f"{out}/keystore")
        cert, key = self.sec[f"own__{node}__fsc__cert.pem"], self.sec[f"own__{node}__fsc__key.pem"]
        with open(f"{out}/signcerts/cert.pem", "w") as f:
            f.write(cert)
        with open(f"{out}/keystore/key.pem", "w") as f:
            f.write(key)
        env = {k: v for k, v in os.environ.items() if not k.startswith("FABRIC_CA")}
        env["FABRIC_CA_CLIENT_HOME"] = tempfile.mkdtemp(dir=self.T)
        a = ["fabric-ca-client", "reenroll", "-u", f"http://127.0.0.1:{self.port}", "-M", out, "--csr.hosts", ",".join(self.want(node)), "--csr.names", NAMES]
        if profile:
            a += ["--enrollment.profile", profile]
        r = subprocess.run(a, capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        with open(f"{out}/signcerts/cert.pem") as f:
            ncert = f.read()
        with open(glob.glob(f"{out}/keystore/*_sk")[0]) as f:
            nkey = f.read()
        return cert, key, ncert, nkey

    def test_reenroll_with_the_current_identity_fixes_the_san_and_rotates_the_key(self):
        for node in self.NODES:
            cert, key, ncert, nkey = self.reenroll(node)
            self.assertEqual(san(ncert), self.want(node), node)
            self.assertEqual(subject(ncert), subject(cert), node)           # same CN/OU/O/ST/C
            self.assertNotEqual(pubkey_fp(nkey, "key"), pubkey_fp(key, "key"), node)   # a new key was generated
            self.assertEqual(pubkey_fp(ncert, "cert"), pubkey_fp(nkey, "key"), node)

    def test_reenroll_tls_profile_gives_the_same_san(self):
        cert, key, ncert, nkey = self.reenroll(self.NODES[1], "tls")
        self.assertEqual(san(ncert), self.want(self.NODES[1]))

    def test_reenroll_needs_a_valid_current_identity(self):
        node = self.NODES[0]
        out = tempfile.mkdtemp(prefix="bad.", dir=self.T)
        os.makedirs(f"{out}/signcerts")
        os.makedirs(f"{out}/keystore")
        with open(f"{out}/signcerts/cert.pem", "w") as f:
            f.write(self.sec[f"own__{node}__fsc__cert.pem"])
        with open(f"{out}/keystore/key.pem", "w") as f:   # the key of ANOTHER node: the CA must refuse
            f.write(self.sec[f"own__{self.NODES[1]}__fsc__key.pem"])
        env = {k: v for k, v in os.environ.items() if not k.startswith("FABRIC_CA")}
        env["FABRIC_CA_CLIENT_HOME"] = tempfile.mkdtemp(dir=self.T)
        r = subprocess.run(["fabric-ca-client", "reenroll", "-u", f"http://127.0.0.1:{self.port}", "-M", out], capture_output=True, text=True, env=env)
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
