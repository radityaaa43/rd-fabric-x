"""R4 `fsc-reenroll --rotate-admin` (multiorg/fsc/reenroll/rotate.go) against the REAL pinned fabric-ca server (docker, throwaway, localhost) and the REAL fabric-ca-client.
Only the Kubernetes API is faked (a Secret `fca-org3-admin` with merge-patch semantics). The helper is compiled from the repo by this test (go build, a few seconds).
Proves what the unit tests cannot: the CA accepts our hand-built PUT token (upstream GenECDSAToken format, low-S), the old admin password is refused afterwards, the new one enrolls,
the Secret ends with ONLY the new `password`, and no password reaches the helper's output.

  REQUIRE_REAL_CA=1 python3 -m unittest multiorg.fsc.test_rotate_admin_real     (CI sets it: missing docker/client/go is then a failure, not a skip)
"""
import base64, json, os, shutil, socket, subprocess, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
IMG = "ghcr.io/hyperledger/fabric-ca@sha256:87c36f0b655838e2c3b00379cafc6efb36dc6f8d88b2cec9c707fd47e93b1c63"
NS, SECRET, START = "rd-fabricx-bank-b", "fca-org3-admin", "start-pw_1"


def have():
    return shutil.which("docker") and shutil.which("fabric-ca-client") and shutil.which("go")


class Api(BaseHTTPRequestHandler):
    data, rv = {}, 10
    patches = []

    def log_message(self, *a):
        pass

    def _send(self, code, obj=None):
        b = json.dumps(obj or {}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _ok(self):
        return self.headers.get("Authorization") == "Bearer tok" and self.path.split("?")[0] == f"/api/v1/namespaces/{NS}/secrets/{SECRET}"

    def do_GET(self):
        if not self._ok():
            return self._send(404)
        self._send(200, {"metadata": {"resourceVersion": str(Api.rv)}, "data": {k: base64.b64encode(v.encode()).decode() for k, v in Api.data.items()}})

    def do_PATCH(self):
        if not self._ok():
            return self._send(404)
        p = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Api.patches.append(p)
        if p.get("metadata", {}).get("resourceVersion") not in (None, str(Api.rv)):
            return self._send(409)
        for k, v in p["data"].items():
            if v is None:
                Api.data.pop(k, None)
            else:
                Api.data[k] = base64.b64decode(v).decode()
        Api.rv += 1
        self._send(200, {"metadata": {"resourceVersion": str(Api.rv)}})


@unittest.skipUnless(have() or os.environ.get("REQUIRE_REAL_CA"), "docker, fabric-ca-client and go needed (CI sets REQUIRE_REAL_CA=1)")
class RotateAdminReal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not have():
            raise AssertionError("REQUIRE_REAL_CA=1 but docker, fabric-ca-client or go is missing")
        cls.T = tempfile.mkdtemp(prefix="rotadm.")
        subprocess.run(["go", "build", "-o", f"{cls.T}/fsc-reenroll", "."], cwd=os.path.join(HERE, "reenroll"), check=True, capture_output=True)
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        cls.port = s.getsockname()[1]
        s.close()
        cls.cid = subprocess.run(["docker", "run", "-d", "--rm", "-p", f"127.0.0.1:{cls.port}:7054", IMG, "fabric-ca-server", "start", "-b", f"admin:{START}", "--tls.enabled=false"],
                                 capture_output=True, text=True, check=True).stdout.strip()
        for _ in range(120):
            if subprocess.run(["curl", "-sf", f"http://127.0.0.1:{cls.port}/cainfo"], capture_output=True).returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("fabric-ca-server did not come up")
        Api.data, Api.rv, Api.patches = {"password": START}, 10, []
        cls.api = ThreadingHTTPServer(("127.0.0.1", 0), Api)
        threading.Thread(target=cls.api.serve_forever, daemon=True).start()
        with open(f"{cls.T}/token", "w") as f:
            f.write("tok")

    @classmethod
    def tearDownClass(cls):
        cls.api.shutdown()
        subprocess.run(["docker", "stop", cls.cid], capture_output=True)
        shutil.rmtree(cls.T, ignore_errors=True)

    def enrolls(self, pw):
        env = {k: v for k, v in os.environ.items() if not k.startswith("FABRIC_CA")}
        env["FABRIC_CA_CLIENT_HOME"] = tempfile.mkdtemp(dir=self.T)
        env["FABRIC_CA_CLIENT_URL"] = f"http://admin:{pw}@127.0.0.1:{self.port}"
        return subprocess.run(["fabric-ca-client", "enroll", "-M", tempfile.mkdtemp(dir=self.T)], capture_output=True, text=True, env=env).returncode == 0

    def rotate(self):
        work = tempfile.mkdtemp(dir=self.T)
        r = subprocess.run([f"{self.T}/fsc-reenroll", "--rotate-admin", "--ca-url", f"http://127.0.0.1:{self.port}", "--secret", SECRET, "--work", work,
                            "--api", f"http://127.0.0.1:{self.api.server_address[1]}", "--ns", NS, "--token-file", f"{self.T}/token"], capture_output=True, text=True)
        return r

    def test_rotation_twice_old_refused_new_enrolls_secret_holds_only_the_new_password(self):
        self.assertTrue(self.enrolls(START), "the CA must start with the bootstrap password")
        prev = Api.data["password"]
        for i in range(2):   # the second run proves the Secret really follows the CA
            r = self.rotate()
            self.assertEqual(r.returncode, 0, r.stderr[-300:] + r.stdout[-300:])
            nw = Api.data["password"]
            self.assertNotEqual(nw, prev)
            self.assertGreaterEqual(len(nw), 40)
            self.assertEqual(sorted(Api.data), ["password"], "password.next must be gone after the promote")
            self.assertTrue(self.enrolls(nw), f"round {i}: the new password must enroll")
            self.assertFalse(self.enrolls(prev), f"round {i}: the previous password must be refused")
            for pw in (prev, nw):
                self.assertNotIn(pw, r.stdout + r.stderr)
                self.assertNotIn(base64.b64encode(pw.encode()).decode(), r.stdout + r.stderr)
            self.assertIn("rotate-admin promote OK", r.stdout)
            prev = nw
        first = Api.patches[0]["data"]
        self.assertEqual(list(first), ["password.next"], "the first write of a run is password.next only")


if __name__ == "__main__":
    unittest.main()
