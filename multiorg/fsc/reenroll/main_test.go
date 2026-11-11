package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"testing"
	"time"
)

const ns, secret, node = "rd-fabricx-bank-b", "rdbi-bank3-files", "endorser-3"

var hosts = "endorser-3,endorser-3.rd-fabricx-bank-b.svc.cluster.local"

func mk(t *testing.T, sans []string) (certPEM, keyPEM string) {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "endorser-3-fsc", OrganizationalUnit: []string{"client"}}, DNSNames: sans, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalPKCS8PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
}

type fake struct {
	t        *testing.T
	oldCert  string
	oldKey   string
	patches  []map[string]any
	queries  []string
	ctypes   []string
	conflict bool
	extra    map[string]string
	srv      *httptest.Server
}

func newFake(t *testing.T, oldCert, oldKey string) *fake {
	f := &fake{t: t, oldCert: oldCert, oldKey: oldKey}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path != "/api/v1/namespaces/"+ns+"/secrets/"+secret {
			w.WriteHeader(404)
			return
		}
		switch r.Method {
		case "GET":
			d := map[string]string{"own__" + node + "__fsc__cert.pem": base64.StdEncoding.EncodeToString([]byte(f.oldCert)), "own__" + node + "__fsc__key.pem": base64.StdEncoding.EncodeToString([]byte(f.oldKey))}
			for k, v := range f.extra {
				d[k] = base64.StdEncoding.EncodeToString([]byte(v))
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "10"}, "data": d})
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			var m map[string]any
			json.Unmarshal(b, &m)
			f.patches = append(f.patches, m)
			f.queries = append(f.queries, r.URL.RawQuery)
			f.ctypes = append(f.ctypes, r.Header.Get("Content-Type"))
			if f.conflict {
				w.WriteHeader(409)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{"resourceVersion": "11"}})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// fakeCA: a shell script standing in for fabric-ca-client: logs argv+env, then installs the prepared new identity into the -M dir.
func fakeCA(t *testing.T, dir, newCert, newKey string) (bin, log string) {
	os.WriteFile(filepath.Join(dir, "newcert"), []byte(newCert), 0o600)
	os.WriteFile(filepath.Join(dir, "newkey"), []byte(newKey), 0o600)
	log = filepath.Join(dir, "ca.log")
	bin = filepath.Join(dir, "fabric-ca-client")
	os.WriteFile(bin, []byte("#!/bin/sh\necho \"$@\" >> "+log+"\nenv | grep -c '^FABRIC_CA_CLIENT_URL' >> "+log+"\nenv | grep '^FABRIC_CA_CLIENT_HOME' >> "+log+"\n"+
		"while [ $# -gt 0 ]; do [ \"$1\" = -M ] && M=$2; shift; done\ncp "+dir+"/newcert $M/signcerts/cert.pem\ncp "+dir+"/newkey $M/keystore/abc_sk\n"), 0o755)
	return
}

type env struct {
	f        *fake
	in, work string
	args     []string
	caLog    string
}

func setup(t *testing.T, newSANs []string, mismatch bool) *env {
	d := t.TempDir()
	oc, ok := mk(t, []string{"bi-server"})
	nc, nk := mk(t, newSANs)
	if mismatch {
		_, nk = mk(t, newSANs)
	}
	f := newFake(t, oc, ok)
	in, work := filepath.Join(d, "in"), filepath.Join(d, "work")
	os.MkdirAll(in, 0o700)
	os.MkdirAll(work, 0o700)
	os.WriteFile(filepath.Join(in, "cert.pem"), []byte(oc), 0o600)
	os.WriteFile(filepath.Join(in, "key.pem"), []byte(ok), 0o600)
	os.WriteFile(filepath.Join(d, "token"), []byte("tok"), 0o600)
	bin, log := fakeCA(t, d, nc, nk)
	args := []string{"--node", node, "--ca-url", "http://fca-org3:7054", "--hosts", hosts, "--names", "C=US,ST=North Carolina,O=Hyperledger", "--secret", secret, "--in", in, "--work", work,
		"--keys", "own__" + node + "__fsc__cert.pem,own__" + node + "__fsc__key.pem", "--gen", "g1", "--api", f.srv.URL, "--ns", ns, "--token-file", filepath.Join(d, "token"), "--ca-bin", bin}
	return &env{f: f, in: in, work: work, args: args, caLog: log}
}

func goodSANs() []string { return strings.Split(hosts, ",") }

func TestHappyPathPatchesNewPairKeepsPrevAndPrintsOnlyThePublicCert(t *testing.T) {
	e := setup(t, goodSANs(), false)
	var out bytes.Buffer
	if err := run(e.args, &out); err != nil {
		t.Fatal(err)
	}
	if len(e.f.patches) != 1 || e.f.ctypes[0] != "application/merge-patch+json" || e.f.queries[0] != "" {
		t.Fatalf("patches=%v ctypes=%v q=%v", len(e.f.patches), e.f.ctypes, e.f.queries)
	}
	p := e.f.patches[0]
	if p["metadata"].(map[string]any)["resourceVersion"] != "10" {
		t.Fatalf("no optimistic concurrency: %v", p["metadata"])
	}
	d := p["data"].(map[string]any)
	if len(d) != 4 {
		t.Fatalf("want 4 keys (new cert/key, prev cert/key), got %v", len(d))
	}
	for _, k := range []string{"own__endorser-3__fsc__cert.pem", "own__endorser-3__fsc__key.pem", "own__endorser-3__fsc__cert.pem.prev-g1", "own__endorser-3__fsc__key.pem.prev-g1"} {
		if _, ok := d[k]; !ok {
			t.Fatalf("missing key %s in %v", k, d)
		}
	}
	prev, _ := base64.StdEncoding.DecodeString(d["own__endorser-3__fsc__cert.pem.prev-g1"].(string))
	if string(prev) != e.f.oldCert {
		t.Fatal("prev cert is not the old cert")
	}
	s := out.String()
	if strings.Contains(s, "PRIVATE KEY") {
		t.Fatal("a private key reached the output")
	}
	for _, w := range []string{"resourceVersion before=10 after=11", "NEW-PUBLIC-CERT-BEGIN", "BEGIN CERTIFICATE", "NEW-PUBLIC-CERT-END"} {
		if !strings.Contains(s, w) {
			t.Fatalf("output lacks %q:\n%s", w, s)
		}
	}
}

func TestCAClientGetsNoCredentialsAndTheCurrentIdentityOnly(t *testing.T) {
	e := setup(t, goodSANs(), false)
	if err := run(e.args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(e.caLog)
	l := string(b)
	for _, w := range []string{"reenroll", "-u http://fca-org3:7054", "--csr.hosts " + hosts, "--csr.names C=US,ST=North Carolina,O=Hyperledger", "\n0\n"} {
		if !strings.Contains(l, w) {
			t.Fatalf("CA call lacks %q: %s", w, l)
		}
	}
	if strings.Contains(l, "@") || strings.Contains(l, "password") {
		t.Fatalf("credentials near the CA call: %s", l)
	}
}

func TestDryRunMakesOnlyDryRunRequestsAndNeverCallsTheCA(t *testing.T) {
	e := setup(t, goodSANs(), false)
	var out bytes.Buffer
	if err := run(append(e.args, "--dry-run"), &out); err != nil {
		t.Fatal(err)
	}
	if len(e.f.patches) != 1 || e.f.queries[0] != "dryRun=All" {
		t.Fatalf("patches=%d q=%v", len(e.f.patches), e.f.queries)
	}
	if _, err := os.Stat(e.caLog); err == nil {
		t.Fatal("the CA client ran in dry-run")
	}
	if !strings.Contains(out.String(), "dry-run OK resourceVersion=10") {
		t.Fatal(out.String())
	}
}

func TestRefusals(t *testing.T) {
	cases := map[string]func() *env{
		"new cert misses a name":                   func() *env { return setup(t, []string{"bi-server"}, false) },
		"new key does not match the new cert":      func() *env { return setup(t, goodSANs(), true) },
		"mounted identity differs from the Secret": func() *env { e := setup(t, goodSANs(), false); c, _ := mk(t, []string{"x"}); e.f.oldCert = c; return e },
		"patch conflict":                           func() *env { e := setup(t, goodSANs(), false); e.f.conflict = true; return e },
	}
	for name, mkEnv := range cases {
		t.Run(name, func(t *testing.T) {
			e := mkEnv()
			var out bytes.Buffer
			err := run(e.args, &out)
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(out.String()+err.Error(), "PRIVATE KEY") {
				t.Fatal("key material in output or error")
			}
			if name != "patch conflict" && len(e.f.patches) != 0 {
				t.Fatalf("PATCH sent despite the refusal: %v", e.f.patches)
			}
		})
	}
}

func TestRemovePrevNullsOnlyTheTwoPrevKeys(t *testing.T) {
	e := setup(t, goodSANs(), false)
	var out bytes.Buffer
	if err := run(append(e.args, "--remove-prev"), &out); err != nil {
		t.Fatal(err)
	}
	d := e.f.patches[0]["data"].(map[string]any)
	if len(d) != 2 || d["own__endorser-3__fsc__cert.pem.prev-g1"] != nil || d["own__endorser-3__fsc__key.pem.prev-g1"] != nil {
		t.Fatalf("%v", d)
	}
	if _, err := os.Stat(e.caLog); err == nil {
		t.Fatal("CA client ran in remove-prev")
	}
}

func TestBadArgs(t *testing.T) {
	for _, a := range [][]string{nil, {"--node", "x"}, {"--node", "a b", "--ca-url", "u", "--hosts", "h", "--secret", "s", "--keys", "k1,k2", "--gen", "g"}} {
		if err := run(a, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", a)
		}
	}
}

// restore-prev: the Secret holds the NEW pair (as keys cert/key) and the OLD pair as .prev-g1; the mode puts the old pair back.
func rollbackEnv(t *testing.T) (*env, string, string) {
	e := setup(t, goodSANs(), false)
	oldC, oldK := mk(t, []string{"bi-server"})
	newC, newK := mk(t, goodSANs())
	e.f.oldCert, e.f.oldKey = newC, newK // the live keys now hold the new pair
	e.f.extra = map[string]string{"own__endorser-3__fsc__cert.pem.prev-g1": oldC, "own__endorser-3__fsc__key.pem.prev-g1": oldK}
	return e, oldC, oldK
}

func TestRestorePrevPutsTheOldPairBackWithAResourceVersionGuard(t *testing.T) {
	e, oldC, oldK := rollbackEnv(t)
	var out bytes.Buffer
	if err := run(append(e.args, "--restore-prev"), &out); err != nil {
		t.Fatal(err)
	}
	if len(e.f.patches) != 1 || e.f.queries[0] != "" || e.f.ctypes[0] != "application/merge-patch+json" {
		t.Fatalf("patches=%d q=%v", len(e.f.patches), e.f.queries)
	}
	p := e.f.patches[0]
	if p["metadata"].(map[string]any)["resourceVersion"] != "10" {
		t.Fatal("no resourceVersion guard")
	}
	d := p["data"].(map[string]any)
	if len(d) != 2 {
		t.Fatalf("want exactly the two live keys, got %v", d)
	}
	gc, _ := base64.StdEncoding.DecodeString(d["own__endorser-3__fsc__cert.pem"].(string))
	gk, _ := base64.StdEncoding.DecodeString(d["own__endorser-3__fsc__key.pem"].(string))
	if string(gc) != oldC || string(gk) != oldK {
		t.Fatal("the restored pair is not the .prev pair")
	}
	s := out.String()
	if strings.Contains(s, "PRIVATE KEY") || !strings.Contains(s, "restore-prev g1 OK resourceVersion before=10 after=11") || !strings.Contains(s, "RESTORED-PUBLIC-CERT-BEGIN") || !strings.Contains(s, oldC) {
		t.Fatalf("output:\n%s", s)
	}
	if _, err := os.Stat(e.caLog); err == nil {
		t.Fatal("the CA client ran in restore-prev")
	}
}

func TestRestorePrevDryRunOnlyDryRuns(t *testing.T) {
	e, _, _ := rollbackEnv(t)
	var out bytes.Buffer
	if err := run(append(e.args, "--restore-prev", "--dry-run"), &out); err != nil {
		t.Fatal(err)
	}
	if len(e.f.patches) != 1 || e.f.queries[0] != "dryRun=All" || !strings.Contains(out.String(), "restore-prev dry-run OK") {
		t.Fatalf("%v %v %s", len(e.f.patches), e.f.queries, out.String())
	}
}

func TestRestorePrevRefusals(t *testing.T) {
	t.Run("no prev keys (already removed)", func(t *testing.T) {
		e, _, _ := rollbackEnv(t)
		e.f.extra = nil
		if err := run(append(e.args, "--restore-prev"), &bytes.Buffer{}); err == nil || len(e.f.patches) != 0 {
			t.Fatalf("err=%v patches=%d", err, len(e.f.patches))
		}
	})
	t.Run("prev cert does not match prev key", func(t *testing.T) {
		e, _, _ := rollbackEnv(t)
		_, otherK := mk(t, []string{"x"})
		e.f.extra["own__endorser-3__fsc__key.pem.prev-g1"] = otherK
		var out bytes.Buffer
		err := run(append(e.args, "--restore-prev"), &out)
		if err == nil || len(e.f.patches) != 0 || strings.Contains(out.String()+err.Error(), "PRIVATE KEY") {
			t.Fatalf("err=%v patches=%d", err, len(e.f.patches))
		}
	})
	t.Run("conflict", func(t *testing.T) {
		e, _, _ := rollbackEnv(t)
		e.f.conflict = true
		if err := run(append(e.args, "--restore-prev"), &bytes.Buffer{}); err == nil {
			t.Fatal("expected the 409 to fail")
		}
	})
}
