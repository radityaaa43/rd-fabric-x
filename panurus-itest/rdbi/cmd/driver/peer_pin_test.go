package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Per-peer pinning (final design D4): the client for gateway M trusts ONLY org M's root CA, so a certificate with the
// name fx-gw-M that another org's CA issued is refused.

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf issues a certificate for the name (and 127.0.0.1, where httptest listens) with both extended key usages.
func (ca *testCA) leaf(t *testing.T, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// peerDir lays out /peer: ca-<M>.crt (org M's root only), tls.crt and tls.key (this gateway's peer identity).
func peerDir(t *testing.T, cas map[int]*testCA) string {
	t.Helper()
	d := t.TempDir()
	for m, ca := range cas {
		if err := os.WriteFile(filepath.Join(d, fmt.Sprintf("ca-%d.crt", m)), ca.pem, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, k := cas[2].leaf(t, "fx-gw-2-peer")
	os.WriteFile(filepath.Join(d, "tls.crt"), c, 0o600)
	os.WriteFile(filepath.Join(d, "tls.key"), k, 0o600)
	return d
}

// gwServer is the gateway of org M: a TLS server whose certificate is signed by `issuer`.
func gwServer(t *testing.T, issuer *testCA) *httptest.Server {
	t.Helper()
	c, k := issuer.leaf(t, "fx-gw-X")
	pair, err := tls.X509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func cas(t *testing.T) map[int]*testCA {
	return map[int]*testCA{1: newCA(t, "root-1"), 2: newCA(t, "root-2"), 3: newCA(t, "root-3"), 4: newCA(t, "root-4")}
}

func TestPeerForTrustsOnlyThatOrgsRoot(t *testing.T) {
	c := cas(t)
	cl, err := peerClients(peerDir(t, c))
	if err != nil {
		t.Fatal(err)
	}
	right := gwServer(t, c[3])
	resp, err := cl[3].Post(right.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("gateway 3 with org 3's certificate must verify: %v", err)
	}
	resp.Body.Close()
	// the certificate of "gateway 3" was issued by org 2's CA: refused by the client for gateway 3
	wrong := gwServer(t, c[2])
	if _, err := cl[3].Post(wrong.URL, "application/json", strings.NewReader("{}")); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Fatalf("gateway 3 with org 2's certificate must be refused (unknown authority), got %v", err)
	}
	// and org 3's certificate is refused by the client for gateway 2
	if _, err := cl[2].Post(right.URL, "application/json", strings.NewReader("{}")); err == nil {
		t.Fatal("the client for gateway 2 must not trust org 3's root")
	}
}

func TestPeerClientsNeedEveryOrgRootAndTheClientCertificate(t *testing.T) {
	c := cas(t)
	d := peerDir(t, c)
	os.Remove(filepath.Join(d, "ca-4.crt"))
	if _, err := peerClients(d); err == nil || !strings.Contains(err.Error(), "ca-4.crt") {
		t.Fatalf("a missing ca-4.crt must fail at start, got %v", err)
	}
	d = peerDir(t, c)
	os.Remove(filepath.Join(d, "tls.key"))
	if _, err := peerClients(d); err == nil {
		t.Fatal("a missing client key must fail at start")
	}
	d = peerDir(t, c)
	os.WriteFile(filepath.Join(d, "ca-1.crt"), []byte("not a certificate"), 0o600)
	if _, err := peerClients(d); err == nil {
		t.Fatal("a ca file without a certificate must fail at start")
	}
}

func TestPeerClientsHoldOneRootEach(t *testing.T) {
	c := cas(t)
	d := peerDir(t, c)
	// a bundle in a ca file (two roots) is refused: one org, one root
	os.WriteFile(filepath.Join(d, "ca-3.crt"), append(append([]byte{}, c[3].pem...), c[2].pem...), 0o600)
	if _, err := peerClients(d); err == nil || !strings.Contains(err.Error(), "ca-3.crt") {
		t.Fatalf("a ca file with two certificates must be refused, got %v", err)
	}
}

func TestProbeBIUsesOrg1RootOnly(t *testing.T) {
	c := cas(t)
	cl, err := peerClients(peerDir(t, c))
	if err != nil {
		t.Fatal(err)
	}
	old, oldClients := peerURL, peers
	t.Cleanup(func() { peerURL, peers = old, oldClients })
	peers = cl
	bi1 := gwServer(t, c[1])
	peerURL = bi1.URL + "/?gw=%d"
	if err := probeBI(); err != nil {
		t.Fatalf("BI's gateway with org 1's certificate must answer: %v", err)
	}
	fake := gwServer(t, c[3]) // a gateway claiming to be BI with another org's certificate
	peerURL = fake.URL + "/?gw=%d"
	if err := probeBI(); err == nil {
		t.Fatal("probeBI must refuse a BI gateway certificate that org 1's CA did not issue")
	}
}
