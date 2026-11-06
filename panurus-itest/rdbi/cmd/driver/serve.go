package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	views1 "github.com/LFDT-Panurus/panurus/integration/token/common/views"
	rep "github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/views"
	"github.com/LFDT-Panurus/panurus/token/token"
)

// serve is the HTTP door of one party's OPA gateway (fx-gw-N, fabric-x/opa/DESIGN.md): Envoy asks OPA about every
// request body, then forwards it here on 127.0.0.1. It holds ONLY the party's own client identity and calls ONLY
// the party's own node, so a request OPA did not allow cannot reach the chain through this pod.
//
//	driver serve <party node> <listen addr>          e.g. driver serve bank2 127.0.0.1:8080
//	driver issuer-id <file>                          writes the issuer's public identity (redeem needs it, not the key)
//
// One JSON object per POST, field "op" picks the operation:
//
//	issue    {to, type, amount}                               BI only
//	award    {id, to, dfabi, rd}                              BI only; prechecked at the bank's gateway
//	transfer {from, to, type, amount}
//	swap     {id, from, to, give:{type,amount}, get:{type,amount}}   DvP; prechecked at the buyer's (to) gateway
//	redeem   {from, type, amount}
//	precheck {id, kind, from, to, give, get}                 the counterparty leg of a swap/award; OPA decides, no chain action
//	balance {type} | history {limit} | records {txid} | finality {txid} | report {txid} | usage {type, since}
var (
	serving bool
	party   string
	gwOf    = map[string]int{bi: 1, "bank2": 2, "bank3": 3, "bank4": 4}
	peerURL = "https://fx-gw-%d:8443/" // the counterparty's gateway (Envoy, mTLS), same namespace
	peer    *http.Client                // mTLS client to the other gateways
	tlsDir  = envOr("FXGW_TLS", "/mtls")
)

// failure carries a must() error up to the request handler instead of exiting the process.
type failure struct{ msg string }

type leg struct {
	Type   string `json:"type"`
	Amount string `json:"amount"`
}

type request struct {
	Op     string `json:"op"`
	ID     string `json:"id,omitempty"`
	Kind   string `json:"kind,omitempty"`
	From   string `json:"from,omitempty"`
	To     string `json:"to,omitempty"`
	Type   string `json:"type,omitempty"`
	Amount string `json:"amount,omitempty"`
	Give   *leg   `json:"give,omitempty"`
	Get    *leg   `json:"get,omitempty"`
	DFABI  string `json:"dfabi,omitempty"`
	RD     string `json:"rd,omitempty"`
	TxID   string `json:"txid,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Since  string `json:"since,omitempty"`
}

type httpError struct {
	code int
	msg  string
}

func (e httpError) Error() string { return e.msg }

func bad(format string, a ...any) error { return httpError{http.StatusBadRequest, fmt.Sprintf(format, a...)} }

func serve(args []string) {
	if len(args) != 2 || gwOf[args[0]] == 0 {
		must(os.ErrInvalid, "usage: serve <issuer|bank2|bank3|bank4> <listen addr>")
	}
	c, err := peerClient()
	must(err, "mTLS client")
	party, serving, peer = args[0], true, c
	srv := &http.Server{Addr: args[1], Handler: http.HandlerFunc(handle), ReadHeaderTimeout: 10 * time.Second}
	must(srv.ListenAndServe(), "listen "+args[1])
}

func peerClient() (*http.Client, error) {
	ca, err := os.ReadFile(filepath.Join(tlsDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("no CA in ca.crt")
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(tlsDir, "tls.crt"), filepath.Join(tlsDir, "tls.key"))
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}}, nil
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	var req request
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	out, err := do(req)
	if err != nil {
		code := http.StatusBadGateway
		var he httpError
		if errors.As(err, &he) {
			code = he.code
		}
		http.Error(w, err.Error(), code)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// do runs one request; a must() failure inside (a view error) comes back as an error, not an exit.
func do(req request) (out any, err error) {
	defer func() {
		if r := recover(); r != nil {
			f, ok := r.(failure)
			if !ok {
				panic(r)
			}
			err = errors.New(f.msg)
		}
	}()
	return dispatch(req)
}

func dispatch(req request) (any, error) {
	switch req.Op {
	case "issue":
		if err := own(bi); err != nil {
			return nil, err
		}
		q, err := qty(req.Amount)
		if err != nil || !bank(req.To) || req.Type == "" {
			return nil, bad("issue needs to (a bank), type, amount")
		}
		return run(bi, nil, func() any {
			return call(bi, "issue", &views.IssueCash{Auditor: auditor, TokenType: token.Type(req.Type), Quantity: q, Recipient: []byte(req.To), RecipientEID: req.To})
		}), nil
	case "award":
		if err := own(bi); err != nil {
			return nil, err
		}
		d, err1 := qty(req.DFABI)
		p, err2 := qty(req.RD)
		if err1 != nil || err2 != nil || !bank(req.To) || req.ID == "" {
			return nil, bad("award needs id, to (a bank), dfabi, rd")
		}
		pc := request{Op: "precheck", ID: req.ID, Kind: "award", From: bi, To: req.To,
			Give: &leg{dfabi, req.DFABI}, Get: &leg{rd, req.RD}}
		if err := precheck(pc); err != nil {
			return nil, err
		}
		return run(bi, nil, func() any { return call(bi, "award", awardInput(req.To, d, p)) }), nil
	case "transfer":
		if err := own(req.From); err != nil {
			return nil, err
		}
		q, err := qty(req.Amount)
		if err != nil || gwOf[req.To] == 0 || req.To == req.From || req.Type == "" {
			return nil, bad("transfer needs from, to (another node), type, amount")
		}
		return run(party, nil, func() any {
			return call(party, "transfer", &views.Transfer{Auditor: auditor, Type: token.Type(req.Type), Amount: q, Recipient: []byte(req.To), RecipientEID: req.To})
		}), nil
	case "swap":
		if err := own(req.From); err != nil {
			return nil, err
		}
		if req.ID == "" || !bank(req.To) || req.To == req.From || req.Give == nil || req.Get == nil {
			return nil, bad("swap needs id, from, to (another bank), give, get")
		}
		g, err1 := qty(req.Give.Amount)
		t, err2 := qty(req.Get.Amount)
		if err1 != nil || err2 != nil || req.Give.Type == "" || req.Get.Type == "" {
			return nil, bad("swap legs need type and amount")
		}
		pc := req
		pc.Op, pc.Kind = "precheck", "swap"
		if err := precheck(pc); err != nil {
			return nil, err
		}
		return run(party, nil, func() any {
			return call(party, "swap", &views.Swap{Auditor: auditor, FromAliceType: token.Type(req.Give.Type), FromAliceAmount: g,
				FromBobType: token.Type(req.Get.Type), FromBobAmount: t, Bob: []byte(req.To)})
		}), nil
	case "redeem":
		if err := own(req.From); err != nil {
			return nil, err
		}
		q, err := qty(req.Amount)
		if err != nil || req.Type == "" {
			return nil, bad("redeem needs from, type, amount")
		}
		id, err := os.ReadFile(filepath.Join(live, "issuer-identity.bin"))
		if err != nil {
			return nil, err
		}
		return run(party, nil, func() any {
			return call(party, "redeem", &views.Redeem{Auditor: auditor, Issuer: bi, IssuerPublicParamsPublicKey: id, Type: token.Type(req.Type), Amount: q})
		}), nil
	case "precheck":
		// OPA already allowed this leg at this gateway (Envoy forwards only then); nothing touches the chain.
		if err := own(req.To); err != nil {
			return nil, err
		}
		return map[string]any{"ok": true, "id": req.ID}, nil
	case "balance":
		return map[string]string{"amount": strconv.FormatUint(balance(party, req.Type), 10)}, nil
	case "history":
		if req.Limit < 1 {
			return nil, bad("history needs limit >= 1")
		}
		return map[string]any{"records": history(party, req.Limit)}, nil
	case "records":
		return map[string]any{"records": records(party, req.TxID)}, nil
	case "finality":
		call(party, "TxFinality", &views1.TxFinality{TxID: req.TxID, Timeout: 90 * time.Second})
		return map[string]any{"txId": req.TxID, "final": true}, nil
	case "report":
		return map[string]any{"report": deliver(req.TxID)}, nil
	case "usage":
		since, err := time.Parse(time.RFC3339, req.Since)
		if err != nil || req.Type == "" {
			return nil, bad("usage needs type and since (RFC 3339)")
		}
		return map[string]string{"amount": strconv.FormatUint(usage(req.Type, since), 10)}, nil
	}
	return nil, bad("unknown op %q", req.Op)
}

// own refuses a request for another party's node: defence in depth behind OPA.
func own(n string) error {
	if n != party {
		return httpError{http.StatusForbidden, fmt.Sprintf("this gateway serves %s, not %q", party, n)}
	}
	return nil
}

func bank(n string) bool { return gwOf[n] > 1 }

func qty(s string) (uint64, error) {
	v, err := strconv.ParseUint(s, 10, 64)
	if err == nil && v == 0 {
		err = errors.New("zero")
	}
	return v, err
}

// deliver (re)sends a transaction's report to BI, as run() does after submitting.
func deliver(tx string) string {
	o, err := tryCall(party, "report", &rep.Report{TxID: tx})
	if err != nil {
		return "not delivered: " + short(err)
	}
	res := map[string]string{}
	jsonUnmarshal(o.([]byte), &res)
	return res[tx]
}

// precheck asks the counterparty's gateway whether its party may give its leg. Any answer but 200, or no answer
// (gateway down), is a deny: the swap is not submitted.
func precheck(req request) error {
	body, _ := json.Marshal(req)
	resp, err := peer.Post(fmt.Sprintf(peerURL, gwOf[req.To]), "application/json", bytes.NewReader(body))
	if err != nil {
		return httpError{http.StatusForbidden, "precheck at " + req.To + " unreachable: " + err.Error()}
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != http.StatusOK {
		return httpError{http.StatusForbidden, fmt.Sprintf("precheck denied at %s: %d %s", req.To, resp.StatusCode, strings.TrimSpace(string(msg)))}
	}
	return nil
}

// usage sums what this party sent out of `typ` since `since` (transfers, DvP legs, redeems), change excluded,
// from its own token records (rd_dfabi_v2). Feeds the bank daily_limit rule and the Kebijakan usage view.
// The record timestamp is when the node stored it, not the commit time.
func usage(typ string, since time.Time) uint64 {
	var raw []struct {
		ActionType   int
		SenderEID    string
		RecipientEID string
		TokenType    string
		Amount       json.Number
		Status       int
		Timestamp    time.Time
	}
	var out any
	if party == bi {
		out = call(bi, "audited", struct{}{})
	} else {
		out = call(party, "acceptedTransactionHistory", &views.ListAcceptedTransactions{From: &since})
	}
	dec := json.NewDecoder(bytes.NewReader(out.([]byte)))
	dec.UseNumber()
	must(dec.Decode(&raw), "decode usage")
	var sum uint64
	for _, r := range raw {
		// ActionType 1 transfer, 2 redeem; Status 3 deleted (enums listed in history)
		if r.SenderEID != party || r.RecipientEID == party || r.TokenType != typ || r.Status == 3 ||
			(r.ActionType != 1 && r.ActionType != 2) || r.Timestamp.Before(since) {
			continue
		}
		v, err := strconv.ParseUint(r.Amount.String(), 10, 64)
		must(err, "usage amount")
		if sum+v < sum {
			must(errors.New("overflow"), "usage sum")
		}
		sum += v
	}
	return sum
}

// issuerID writes the issuer's public identity for the gateways' redeem (they hold no issuer wallet).
func issuerID(file string) {
	must(os.WriteFile(file, issuerIdentity(), 0o644), "write "+file)
	fmt.Println("wrote", file)
}
