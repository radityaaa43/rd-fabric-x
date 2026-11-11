// Command fsc-reenroll re-issues ONE FSC identity cert inside the org's namespace (fabricx S13 SAN fix).
//
// The FSC websocket p2p listener serves the node identity cert (fsc/cert.pem), so its SAN must carry the names peers dial. This runs in a time-boxed Job under the Job's own
// ServiceAccount (Role: secrets get+patch on ONE Secret): it mounts the CURRENT cert+key read-only, runs `fabric-ca-client reenroll` authenticated by that identity only (no CA admin
// password, no FABRIC_CA_CLIENT_URL credentials), checks the result, and merge-patches the SAME Secret: new cert/key, the old pair kept as <key>.prev-<gen>.
// The output carries exit information, the Secret resourceVersion before/after and the NEW PUBLIC cert only; a private key never reaches stdout.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const sa = "/var/run/secrets/kubernetes.io/serviceaccount/"

var safe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type cfg struct {
	node, caURL, hosts, names, secret, in, work, keys, gen, api, ns, tokenFile, apiCA, caBin string
	dryRun, removePrev                                                                       bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fsc-reenroll: FAILED:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	var c cfg
	fs := flag.NewFlagSet("fsc-reenroll", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for name, dst := range map[string]*string{"node": &c.node, "ca-url": &c.caURL, "hosts": &c.hosts, "names": &c.names, "secret": &c.secret, "in": &c.in, "work": &c.work, "keys": &c.keys, "gen": &c.gen,
		"api": &c.api, "ns": &c.ns, "token-file": &c.tokenFile, "api-ca": &c.apiCA, "ca-bin": &c.caBin} {
		fs.StringVar(dst, name, "", "")
	}
	fs.BoolVar(&c.dryRun, "dry-run", false, "")
	fs.BoolVar(&c.removePrev, "remove-prev", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if c.api == "" {
		c.api = "https://kubernetes.default.svc"
	}
	if c.tokenFile == "" {
		c.tokenFile = sa + "token"
	}
	if c.apiCA == "" && strings.HasPrefix(c.api, "https://") {
		c.apiCA = sa + "ca.crt"
	}
	if c.ns == "" {
		b, err := os.ReadFile(sa + "namespace")
		if err != nil {
			return errors.New("--ns missing and no namespace file")
		}
		c.ns = strings.TrimSpace(string(b))
	}
	if c.caBin == "" {
		c.caBin = "fabric-ca-client"
	}
	keys := strings.Split(c.keys, ",")
	if len(keys) != 2 || !safe.MatchString(c.node) || !safe.MatchString(c.secret) || !safe.MatchString(c.gen) || !safe.MatchString(keys[0]) || !safe.MatchString(keys[1]) || c.hosts == "" || c.caURL == "" {
		return errors.New("need --node --ca-url --hosts --secret --keys cert,key --gen (safe characters only)")
	}
	prev := []string{keys[0] + ".prev-" + c.gen, keys[1] + ".prev-" + c.gen}
	tok, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return err
	}
	api := &client{base: c.api, ns: c.ns, secret: c.secret, token: strings.TrimSpace(string(tok)), http: httpClient(c.apiCA)}

	if c.removePrev { // the separate, recorded step after acceptance: delete ONLY the two .prev-<gen> keys
		rv, _, err := api.patch(map[string]any{"data": map[string]any{prev[0]: nil, prev[1]: nil}}, false)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "remove-prev %s OK resourceVersion=%s\n", c.gen, rv)
		return nil
	}

	oldCert, err := os.ReadFile(filepath.Join(c.in, "cert.pem"))
	if err != nil {
		return err
	}
	oldKey, err := os.ReadFile(filepath.Join(c.in, "key.pem"))
	if err != nil {
		return err
	}
	rvBefore, data, err := api.get()
	if err != nil {
		return err
	}
	if data[keys[0]] != string(oldCert) {
		return errors.New("the mounted identity cert differs from the Secret's: refusing (stale mount)")
	}
	if c.dryRun { // a harmless REAL request with the real SA token: GET above + a dry-run PATCH of the same verb the live run uses
		if _, _, err := api.patch(map[string]any{"metadata": map[string]any{"annotations": map[string]any{"fsc-reenroll/dry-run": c.gen}}}, true); err != nil {
			return err
		}
		fmt.Fprintf(out, "dry-run OK resourceVersion=%s (GET + PATCH dryRun=All, nothing changed, the CA client did not run)\n", rvBefore)
		return nil
	}

	msp := filepath.Join(c.work, "msp")
	for _, d := range []string{"signcerts", "keystore"} {
		if err := os.MkdirAll(filepath.Join(msp, d), 0o700); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(msp, "signcerts", "cert.pem"), oldCert, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(msp, "keystore", "key.pem"), oldKey, 0o600); err != nil {
		return err
	}
	cmd := exec.Command(c.caBin, "reenroll", "-u", c.caURL, "-M", msp, "--csr.hosts", c.hosts, "--csr.names", c.names)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "FABRIC_CA_CLIENT_HOME=" + filepath.Join(c.work, "home")}
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("fabric-ca-client reenroll failed: %v (output withheld: %d bytes)", err, len(b))
	}
	newCert, err := os.ReadFile(filepath.Join(msp, "signcerts", "cert.pem"))
	if err != nil {
		return err
	}
	ks, _ := filepath.Glob(filepath.Join(msp, "keystore", "*_sk"))
	if len(ks) != 1 {
		return fmt.Errorf("want exactly one new key in the keystore, found %d", len(ks))
	}
	newKey, err := os.ReadFile(ks[0])
	if err != nil {
		return err
	}
	if err := verify(oldCert, newCert, newKey, strings.Split(c.hosts, ",")); err != nil {
		return err
	}
	patch := map[string]any{"metadata": map[string]any{"resourceVersion": rvBefore}, "data": map[string]any{
		keys[0]: b64(newCert), keys[1]: b64(newKey), prev[0]: b64(oldCert), prev[1]: b64(oldKey)}}
	rvAfter, _, err := api.patch(patch, false)
	if err != nil {
		return err
	}
	if bytes.Contains(newCert, []byte("PRIVATE KEY")) {
		return errors.New("refusing to print: the cert file holds key material")
	}
	fmt.Fprintf(out, "node=%s secret=%s keys=%s,%s kept=%s,%s\nresourceVersion before=%s after=%s\nNEW-PUBLIC-CERT-BEGIN\n%sNEW-PUBLIC-CERT-END\n",
		c.node, c.secret, keys[0], keys[1], prev[0], prev[1], rvBefore, rvAfter, newCert)
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// verify: the new cert carries every name, has the old subject, and its public key belongs to the new key.
func verify(oldCert, newCert, newKey []byte, names []string) error {
	oc, err := parseCert(oldCert)
	if err != nil {
		return err
	}
	nc, err := parseCert(newCert)
	if err != nil {
		return err
	}
	if _, err := tls.X509KeyPair(newCert, newKey); err != nil {
		return errors.New("the new cert and the new key do not match")
	}
	for _, n := range names {
		if !contains(nc.DNSNames, n) {
			return fmt.Errorf("the new cert lacks the name %q (has %v)", n, nc.DNSNames)
		}
	}
	if nc.Subject.String() != oc.Subject.String() {
		return fmt.Errorf("subject changed: %q -> %q", oc.Subject, nc.Subject)
	}
	return nil
}

func parseCert(p []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("not a PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

type client struct {
	base, ns, secret, token string
	http                    *http.Client
}

func httpClient(caFile string) *http.Client {
	t := &http.Transport{}
	if caFile != "" {
		if b, err := os.ReadFile(caFile); err == nil {
			p := x509.NewCertPool()
			p.AppendCertsFromPEM(b)
			t.TLSClientConfig = &tls.Config{RootCAs: p, MinVersion: tls.VersionTLS12}
		}
	}
	return &http.Client{Transport: t, Timeout: 30 * time.Second}
}

func (c *client) url() string {
	return fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", c.base, c.ns, c.secret)
}

func (c *client) do(method, url, ctype string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	return b, resp.StatusCode, nil
}

// get returns the resourceVersion and the DECODED data of the Secret (the values stay in memory, never printed).
func (c *client) get() (string, map[string]string, error) {
	b, code, err := c.do("GET", c.url(), "", nil)
	if err != nil || code != 200 {
		return "", nil, fmt.Errorf("GET secret: status %d %v", code, err)
	}
	var s struct {
		Metadata struct{ ResourceVersion string } `json:"metadata"`
		Data     map[string]string                `json:"data"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return "", nil, err
	}
	out := map[string]string{}
	for k, v := range s.Data {
		d, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "", nil, err
		}
		out[k] = string(d)
	}
	return s.Metadata.ResourceVersion, out, nil
}

func (c *client) patch(body map[string]any, dry bool) (string, int, error) {
	b, _ := json.Marshal(body)
	u := c.url()
	if dry {
		u += "?dryRun=All"
	}
	r, code, err := c.do("PATCH", u, "application/merge-patch+json", b)
	if err != nil || code != 200 {
		return "", code, fmt.Errorf("PATCH secret: status %d %v", code, err)
	}
	var s struct {
		Metadata struct{ ResourceVersion string } `json:"metadata"`
	}
	json.Unmarshal(r, &s)
	return s.Metadata.ResourceVersion, code, nil
}
