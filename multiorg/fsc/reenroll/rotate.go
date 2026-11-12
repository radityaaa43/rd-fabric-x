package main

// rotate-admin: change the password of the CA's bootstrap identity `admin` and make the Secret follow, inside the CA's own namespace (fabricx R4).
//
// Why a Job: `fabric-ca-server start -b admin:$ADMIN_PASS` only bootstraps an EMPTY registry, so replacing the Secret alone changes nothing: the new password has to be set AT the CA, and nobody
// reads that Secret (not party-admin, not the operator). State machine (a crash can never lock the CA out):
//  1. read Secret `password` (old) and, if present, `password.next` (a new password written by an earlier, interrupted run);
//  2. old enrolls, new does not yet: write `password.next` FIRST (resourceVersion guarded), enroll admin, PUT /api/v1/identities/admin {"id","secret"} with the same token the CA client builds,
//     verify the new password enrolls and the old one is refused;
//  3. merge-patch `password` = new and `password.next` = null.
//     Re-run: old refused but `password.next` enrolls = only step 3 (promote); neither enrolls = stop (no guessing).
//
// Credentials only travel in the environment of the CA client (FABRIC_CA_CLIENT_URL) and in the Secret: never in argv, never in output. The output carries step names and resourceVersions only.
// The PUT is built here because `fabric-ca-client identity modify --secret` takes the value as a command line argument. Token format: upstream fabric-ca v1.5.15 util/util.go GenECDSAToken
// (payload = METHOD.b64(uri).b64(body).b64(certPEM); SHA-256; ECDSA DER, low-S; token = b64(certPEM).b64(sig)).

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	pwKey     = "password"
	pwNextKey = "password.next"
	caAdmin   = "admin"
)

func rotateAdmin(c *cfg, out io.Writer) error {
	if !safe.MatchString(c.secret) || c.caURL == "" || c.work == "" {
		return errors.New("rotate-admin needs --ca-url --secret --work (safe characters only)")
	}
	u, err := url.Parse(c.caURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" {
		return errors.New("--ca-url must be http(s)://host:port with no credentials and no path")
	}
	tok, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return err
	}
	api := &client{base: c.api, ns: c.ns, secret: c.secret, token: strings.TrimSpace(string(tok)), http: httpClient(c.apiCA)}
	rv, data, err := api.get()
	if err != nil {
		return err
	}
	oldPw, nextPw := data[pwKey], data[pwNextKey]
	if oldPw == "" {
		return fmt.Errorf("the Secret has no %q key", pwKey)
	}
	ca := &caConn{base: strings.TrimRight(c.caURL, "/"), url: u, work: c.work, bin: c.caBin, http: http.DefaultClient}
	oldOK := ca.enroll("old", oldPw) == nil
	nextOK := nextPw != "" && ca.enroll("next", nextPw) == nil

	switch {
	case !oldOK && nextOK: // an earlier run changed the CA and stopped before the Secret was promoted
		return promote(api, out, c.secret, rv, nextPw, "promote")
	case !oldOK:
		return errors.New("neither the current password nor password.next enrolls at the CA: stopping (no guessing)")
	case nextOK: // old still enrolls AND next enrolls: the CA was not changed to next by us; refuse rather than guess
		return errors.New("both passwords enroll: unexpected state, stopping")
	}

	newPw := nextPw // an interrupted run already wrote one: reuse it (the CA never took it, nextOK is false)
	if newPw == "" {
		if newPw, err = randomPassword(); err != nil {
			return err
		}
	}
	rv1, _, err := api.patch(map[string]any{"metadata": map[string]any{"resourceVersion": rv}, "data": map[string]any{pwNextKey: b64([]byte(newPw))}}, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rotate-admin step1 password.next written resourceVersion=%s\n", rv1)
	if err := ca.setAdminSecret(newPw); err != nil {
		return err
	}
	fmt.Fprintln(out, "rotate-admin step2 CA accepted the new admin secret")
	if err := ca.enroll("verify-new", newPw); err != nil {
		return errors.New("verify: the NEW password does not enroll after the change: " + err.Error())
	}
	if ca.enroll("verify-old", oldPw) == nil {
		return errors.New("verify: the OLD password still enrolls after the change")
	}
	fmt.Fprintln(out, "rotate-admin verify new enrolls, old refused")
	return promote(api, out, c.secret, rv1, newPw, "promote")
}

func promote(api *client, out io.Writer, secret, rv, newPw, what string) error {
	rv2, _, err := api.patch(map[string]any{"metadata": map[string]any{"resourceVersion": rv}, "data": map[string]any{pwKey: b64([]byte(newPw)), pwNextKey: nil}}, false)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "rotate-admin %s OK secret=%s resourceVersion=%s\n", what, secret, rv2)
	return nil
}

func randomPassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type caConn struct {
	base, work, bin string
	url             *url.URL
	http            *http.Client
	lastMSP         string
}

// enroll runs the real CA client with the credentials in its ENVIRONMENT only; the MSP lands in a per-tag directory of the memory work dir. Output is withheld.
func (a *caConn) enroll(tag, pw string) error {
	home, msp := filepath.Join(a.work, "home-"+tag), filepath.Join(a.work, "msp-"+tag)
	u := *a.url
	u.User = url.UserPassword(caAdmin, pw)
	cmd := exec.Command(a.bin, "enroll", "-M", msp)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "FABRIC_CA_CLIENT_HOME=" + home, "FABRIC_CA_CLIENT_URL=" + u.String()}
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("fabric-ca-client enroll (%s) failed: %v (output withheld: %d bytes)", tag, err, len(b))
	}
	a.lastMSP = msp
	return nil
}

// setAdminSecret PUTs the new secret for `admin` with a token made from the admin enrollment of the LAST successful enroll (the old password's).
func (a *caConn) setAdminSecret(newPw string) error {
	cert, err := os.ReadFile(filepath.Join(a.lastMSP, "signcerts", "cert.pem"))
	if err != nil {
		return err
	}
	ks, _ := filepath.Glob(filepath.Join(a.lastMSP, "keystore", "*_sk"))
	if len(ks) != 1 {
		return fmt.Errorf("want exactly one admin key in the keystore, found %d", len(ks))
	}
	kb, err := os.ReadFile(ks[0])
	if err != nil {
		return err
	}
	key, err := parseECKey(kb)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{"id": caAdmin, "secret": newPw})
	const uri = "/api/v1/identities/" + caAdmin
	token, err := caToken(cert, key, "PUT", uri, body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", a.base+uri, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20)) // the CA echoes the secret in its answer: never read it into the output
	if resp.StatusCode != 200 {
		return fmt.Errorf("CA answered HTTP %d to the identity modify (body withheld)", resp.StatusCode)
	}
	return nil
}

func parseECKey(p []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("admin key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(b.Bytes); err == nil {
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			return ek, nil
		}
		return nil, errors.New("admin key is not an EC key")
	}
	return x509.ParseECPrivateKey(b.Bytes)
}

// caToken: upstream fabric-ca util.GenECDSAToken.
func caToken(certPEM []byte, key *ecdsa.PrivateKey, method, uri string, body []byte) (string, error) {
	enc := base64.StdEncoding.EncodeToString
	b64cert := enc(certPEM)
	payload := method + "." + enc([]byte(uri)) + "." + enc(body) + "." + b64cert
	d := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		return "", err
	}
	if half := new(big.Int).Rsh(key.Curve.Params().N, 1); s.Cmp(half) > 0 { // bccsp requires low-S
		s.Sub(key.Curve.Params().N, s)
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return "", err
	}
	return b64cert + "." + enc(der), nil
}
