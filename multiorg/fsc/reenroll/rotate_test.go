package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const caSecret = "fca-org3-admin"

// k8sFake is a Secret `fca-org3-admin` with merge-patch semantics (null deletes a key) and a resourceVersion guard.
type k8sFake struct {
	mu      sync.Mutex
	t       *testing.T
	data    map[string]string
	rv      int
	patches []map[string]any
	srv     *httptest.Server
}

func newK8s(t *testing.T, data map[string]string) *k8sFake {
	f := &k8sFake{t: t, data: data, rv: 10}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/api/v1/namespaces/"+ns+"/secrets/"+caSecret {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case "GET":
			enc := map[string]string{}
			for k, v := range f.data {
				enc[k] = base64.StdEncoding.EncodeToString([]byte(v))
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": itoa(f.rv)}, "data": enc})
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			var p map[string]any
			json.Unmarshal(b, &p)
			f.patches = append(f.patches, p)
			if md, ok := p["metadata"].(map[string]any); ok && md["resourceVersion"] != itoa(f.rv) {
				w.WriteHeader(409)
				return
			}
			for k, v := range p["data"].(map[string]any) {
				if v == nil {
					delete(f.data, k)
					continue
				}
				d, _ := base64.StdEncoding.DecodeString(v.(string))
				f.data[k] = string(d)
			}
			f.rv++
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": itoa(f.rv)}})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

// caFake is the CA: the admin password lives in dir/capw; the fake `fabric-ca-client` enrolls when FABRIC_CA_CLIENT_URL carries it; PUT /api/v1/identities/admin verifies the token like
// upstream fabric-ca (util.VerifyToken): payload METHOD.b64(uri).b64(body).b64(cert), SHA-256, ECDSA DER, low-S.
type caFake struct {
	dir, bin string
	srv      *httptest.Server
	puts     int
	ignore   bool // accept the PUT with 200 but change nothing
	status   int  // non-zero: answer this status
}

func newCA(t *testing.T, pw string) *caFake {
	d := t.TempDir()
	cert, key := mk(t, nil)
	os.WriteFile(filepath.Join(d, "cert"), []byte(cert), 0o600)
	os.WriteFile(filepath.Join(d, "key"), []byte(key), 0o600)
	os.WriteFile(filepath.Join(d, "capw"), []byte(pw), 0o600)
	bin := filepath.Join(d, "fabric-ca-client")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + d + "/argv.log\n" +
		"if [ -n \"$FABRIC_CA_CLIENT_URL\" ]; then echo present >> " + d + "/env.log; fi\n" +
		"pw=$(printf '%s' \"$FABRIC_CA_CLIENT_URL\" | sed -e 's|^[a-z]*://admin:||' -e 's|@.*||')\n" +
		"[ \"$pw\" = \"$(cat " + d + "/capw)\" ] || { echo denied >&2; exit 1; }\n" +
		"M=$3\nmkdir -p $M/signcerts $M/keystore\ncp " + d + "/cert $M/signcerts/cert.pem\ncp " + d + "/key $M/keystore/abc_sk\n"
	os.WriteFile(bin, []byte(script), 0o755)
	c := &caFake{dir: d, bin: bin}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "PUT" || r.URL.RequestURI() != "/api/v1/identities/admin" {
			w.WriteHeader(404)
			return
		}
		if err := verifyUpstream(r.Header.Get("Authorization"), r.Method, r.URL.RequestURI(), body); err != "" {
			t.Errorf("CA fake rejects the token: %s", err)
			w.WriteHeader(401)
			return
		}
		c.puts++
		if c.status != 0 {
			w.WriteHeader(c.status)
			return
		}
		var req struct{ ID, Secret string }
		json.Unmarshal(body, &req)
		if req.ID != "admin" || req.Secret == "" {
			w.WriteHeader(400)
			return
		}
		if !c.ignore {
			os.WriteFile(filepath.Join(d, "capw"), []byte(req.Secret), 0o600)
		}
		json.NewEncoder(w).Encode(map[string]any{"id": "admin"}) // the real CA also echoes the secret: the helper must never print the answer
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func verifyUpstream(token, method, uri string, body []byte) string {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "token is not b64cert.b64sig"
	}
	certPEM, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return "bad cert b64"
	}
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return "cert is not PEM"
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err.Error()
	}
	sig, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "bad sig b64"
	}
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) != 0 {
		return "signature is not DER"
	}
	pub := cert.PublicKey.(*ecdsa.PublicKey)
	if rs.S.Cmp(new(big.Int).Rsh(pub.Curve.Params().N, 1)) > 0 {
		return "S is not low"
	}
	enc := base64.StdEncoding.EncodeToString
	d := sha256.Sum256([]byte(method + "." + enc([]byte(uri)) + "." + enc(body) + "." + parts[0]))
	if !ecdsa.Verify(pub, d[:], rs.R, rs.S) {
		return "signature does not verify"
	}
	return ""
}

func rotateArgs(k *k8sFake, ca *caFake, dir string) []string {
	os.WriteFile(filepath.Join(dir, "token"), []byte("tok"), 0o600)
	work := filepath.Join(dir, "work")
	os.MkdirAll(work, 0o700)
	return []string{"--rotate-admin", "--ca-url", ca.srv.URL, "--secret", caSecret, "--work", work, "--api", k.srv.URL, "--ns", ns, "--token-file", filepath.Join(dir, "token"), "--ca-bin", ca.bin}
}

func caPw(ca *caFake) string { b, _ := os.ReadFile(filepath.Join(ca.dir, "capw")); return string(b) }
func logOf(ca *caFake, f string) string {
	b, _ := os.ReadFile(filepath.Join(ca.dir, f))
	return string(b)
}

func TestRotateAdminChangesTheCAThenThePasswordKeyAndPrintsNoSecret(t *testing.T) {
	ca := newCA(t, "oldpw-1")
	k := newK8s(t, map[string]string{"password": "oldpw-1"})
	var out bytes.Buffer
	if err := run(rotateArgs(k, ca, t.TempDir()), &out); err != nil {
		t.Fatal(err)
	}
	nw := caPw(ca)
	if nw == "oldpw-1" || len(nw) < 40 {
		t.Fatalf("the CA password did not change to a long random one: %q", nw)
	}
	if k.data["password"] != nw || len(k.data) != 1 {
		t.Fatalf("Secret keys %v, want only password == the CA's new password", keysOf(k.data))
	}
	if len(k.patches) != 2 {
		t.Fatalf("want 2 patches (password.next first, then promote), got %d", len(k.patches))
	}
	first := k.patches[0]["data"].(map[string]any)
	if _, ok := first["password.next"]; !ok || len(first) != 1 || k.patches[0]["metadata"] == nil {
		t.Fatalf("step 1 must write ONLY password.next, guarded by resourceVersion: %v", keysOfAny(first))
	}
	last := k.patches[1]["data"].(map[string]any)
	if last["password.next"] != nil || last["password"] == nil {
		t.Fatalf("promote must set password and null password.next: %v", last)
	}
	if ca.puts != 1 {
		t.Fatalf("want exactly one identity modify, got %d", ca.puts)
	}
	for _, s := range []string{"oldpw-1", nw, base64.StdEncoding.EncodeToString([]byte(nw)), base64.StdEncoding.EncodeToString([]byte("oldpw-1"))} {
		if strings.Contains(out.String(), s) {
			t.Fatalf("the output contains a password: %q", out.String())
		}
	}
	if !strings.Contains(out.String(), "rotate-admin promote OK") {
		t.Fatalf("output: %q", out.String())
	}
	argv := logOf(ca, "argv.log")
	if strings.Contains(argv, "oldpw-1") || strings.Contains(argv, nw) || strings.Contains(argv, "admin:") {
		t.Fatalf("a password reached the CA client's argv: %q", argv)
	}
	if got := strings.Count(logOf(ca, "env.log"), "present"); got != 3 {
		t.Fatalf("want 3 enrolls (old, verify-new, verify-old) with the URL in the environment, got %d", got)
	}
}

func TestRotateAdminPromotesWhenAnEarlierRunAlreadyChangedTheCA(t *testing.T) {
	ca := newCA(t, "newpw-2")
	k := newK8s(t, map[string]string{"password": "oldpw-1", "password.next": "newpw-2"})
	var out bytes.Buffer
	if err := run(rotateArgs(k, ca, t.TempDir()), &out); err != nil {
		t.Fatal(err)
	}
	if ca.puts != 0 || len(k.patches) != 1 || k.data["password"] != "newpw-2" || k.data["password.next"] != "" || len(k.data) != 1 {
		t.Fatalf("promote only: puts=%d patches=%d keys=%v", ca.puts, len(k.patches), keysOf(k.data))
	}
}

func TestRotateAdminReusesAPasswordNextTheCANeverTook(t *testing.T) {
	ca := newCA(t, "oldpw-1")
	k := newK8s(t, map[string]string{"password": "oldpw-1", "password.next": "pending-3"})
	if err := run(rotateArgs(k, ca, t.TempDir()), io.Discard); err != nil {
		t.Fatal(err)
	}
	if caPw(ca) != "pending-3" || k.data["password"] != "pending-3" {
		t.Fatalf("the stored password.next must be the one used: CA %q Secret %q", caPw(ca), k.data["password"])
	}
}

func TestRotateAdminStopsWhenNeitherPasswordEnrolls(t *testing.T) {
	ca := newCA(t, "someone-else")
	k := newK8s(t, map[string]string{"password": "oldpw-1", "password.next": "pending-3"})
	if err := run(rotateArgs(k, ca, t.TempDir()), io.Discard); err == nil || len(k.patches) != 0 || ca.puts != 0 {
		t.Fatalf("want a refusal with no write: err=%v patches=%d puts=%d", err, len(k.patches), ca.puts)
	}
}

func TestRotateAdminRefusesWhenBothEnroll(t *testing.T) {
	ca := newCA(t, "same-pw")
	k := newK8s(t, map[string]string{"password": "same-pw", "password.next": "same-pw"})
	if err := run(rotateArgs(k, ca, t.TempDir()), io.Discard); err == nil || len(k.patches) != 0 || ca.puts != 0 {
		t.Fatalf("want a refusal with no write: err=%v patches=%d puts=%d", err, len(k.patches), ca.puts)
	}
}

func TestRotateAdminCAErrorLeavesPasswordNextAndNeverPromotes(t *testing.T) {
	ca := newCA(t, "oldpw-1")
	ca.status = 403
	k := newK8s(t, map[string]string{"password": "oldpw-1"})
	err := run(rotateArgs(k, ca, t.TempDir()), io.Discard)
	if err == nil || strings.Contains(err.Error(), "oldpw-1") {
		t.Fatalf("want an error without the password: %v", err)
	}
	if k.data["password"] != "oldpw-1" || k.data["password.next"] == "" || len(k.patches) != 1 {
		t.Fatalf("state after a CA refusal: keys=%v patches=%d", keysOf(k.data), len(k.patches))
	}
}

func TestRotateAdminFailsWhenTheOldPasswordStillWorksAfterTheChange(t *testing.T) {
	ca := newCA(t, "oldpw-1")
	ca.ignore = true
	k := newK8s(t, map[string]string{"password": "oldpw-1"})
	err := run(rotateArgs(k, ca, t.TempDir()), io.Discard)
	if err == nil || len(k.patches) != 1 || k.data["password"] != "oldpw-1" {
		t.Fatalf("want a verify failure without promote: err=%v patches=%d", err, len(k.patches))
	}
}

func TestRotateAdminRefusesBadCAURLs(t *testing.T) {
	ca := newCA(t, "oldpw-1")
	for _, bad := range []string{"http://admin:oldpw-1@fca-org3:7054", "ftp://fca-org3:7054", "http://fca-org3:7054/api/v1", "http://", ""} {
		k := newK8s(t, map[string]string{"password": "oldpw-1"})
		args := rotateArgs(k, ca, t.TempDir())
		for i, a := range args {
			if a == "--ca-url" {
				args[i+1] = bad
			}
		}
		if err := run(args, io.Discard); err == nil || len(k.patches) != 0 {
			t.Fatalf("%q: want a refusal with no write, err=%v patches=%d", bad, err, len(k.patches))
		}
	}
}

func TestCATokenIsAlwaysLowSAndVerifiesLikeUpstream(t *testing.T) {
	cert, key := mk(t, nil)
	k, err := parseECKey([]byte(key))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ { // about half of raw ECDSA signatures have a high S
		body := []byte(`{"id":"admin","secret":"x` + itoa(i) + `"}`)
		tok, err := caToken([]byte(cert), k, "PUT", "/api/v1/identities/admin", body)
		if err != nil {
			t.Fatal(err)
		}
		if msg := verifyUpstream(tok, "PUT", "/api/v1/identities/admin", body); msg != "" {
			t.Fatalf("round %d: %s", i, msg)
		}
		if verifyUpstream(tok, "PUT", "/api/v1/identities/other", body) == "" {
			t.Fatal("a token for another URI must not verify")
		}
	}
}

func keysOf(m map[string]string) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

func keysOfAny(m map[string]any) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}
