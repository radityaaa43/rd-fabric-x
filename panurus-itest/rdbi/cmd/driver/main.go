// Command driver runs the RD/DFABI scenario against the token nodes started by scripts/run.sh.
// It calls the same views as the integration test (issue, transfer, swap, redeem, balance, audit)
// over each node's gRPC view API.
//
//	driver setup-pp        install the public parameters into namespace rd_dfabi (once per namespace)
//	driver scenario        issue, transfer, DvP swap and burn, then check balances
//	driver negative        attempts that must be rejected without changing any balance
//	driver transfer <from> <to> <type> <amount>
//	driver swap <from> <to> <type from gives> <amount> <type to gives> <amount>   (DvP)
//	driver balance <node> <type>
//	driver report          every node reports what it holds to BI (catch-up after BI was offline); lists gaps
//	driver audited         BI's audit records
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	views1 "github.com/LFDT-Panurus/panurus/integration/token/common/views"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/views"
	rep "github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
	"github.com/LFDT-Panurus/panurus/integration/token/fungible/views/ppsetup"
	"github.com/LFDT-Panurus/panurus/token/services/identity"
	"github.com/LFDT-Panurus/panurus/token/services/identity/x509"
	"github.com/LFDT-Panurus/panurus/token/services/identity/x509/crypto"
	"github.com/LFDT-Panurus/panurus/token/services/storage/db/kvs"
	"github.com/LFDT-Panurus/panurus/token/token"
	"github.com/hyperledger-labs/fabric-smart-client/platform/common/services/grpc"
	"github.com/hyperledger-labs/fabric-smart-client/platform/view/services/tracing"
	client "github.com/hyperledger-labs/fabric-smart-client/platform/view/services/view/grpc/client"
	"gopkg.in/yaml.v3"
)

const (
	rd    = "RD"
	dfabi = "DFABI-2027A"
	bi    = "issuer" // BI: issuer and DFABI custodian
	// auditor is empty: the public parameters list no auditor, so no node has to co-sign token requests
	// and banks keep transacting while BI is offline.
	auditor = ""
)

var live = filepath.Join(os.Getenv("HOME"), ".fabricx-token", "live")

func must(err error, what string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", what, err)
		os.Exit(1)
	}
}

type viewClient interface {
	CallView(fid string, in []byte) (any, error)
}

var clients = map[string]viewClient{}

// node returns the gRPC view client of a node, built from the client-config.yaml NWO generated for it.
func node(name string) viewClient {
	if c, ok := clients[name]; ok {
		return c
	}
	raw, err := os.ReadFile(filepath.Join(live, name, "client-config.yaml"))
	must(err, "read client-config "+name)
	var cfg struct {
		Address   string `yaml:"address"`
		TLSConfig struct {
			PeerCACertPath string `yaml:"peercacertpath"`
		} `yaml:"tlsconfig"`
		SignerConfig struct {
			IdentityPath string `yaml:"identitypath"`
			KeyPath      string `yaml:"keypath"`
		} `yaml:"signerconfig"`
	}
	must(yaml.Unmarshal(raw, &cfg), "parse client-config "+name)
	ca, err := os.ReadFile(cfg.TLSConfig.PeerCACertPath)
	must(err, "read tls ca")
	sid, err := client.NewX509SigningIdentity(cfg.SignerConfig.IdentityPath, cfg.SignerConfig.KeyPath)
	must(err, "signing identity "+name)
	tp, err := tracing.NewProviderFromConfig(tracing.Config{Provider: tracing.None})
	must(err, "tracing")
	c, err := client.NewClient(&client.Config{ID: name, ConnectionConfig: &grpc.ConnectionConfig{
		Address: cfg.Address, ConnectionTimeout: 10 * time.Minute,
		TLS: grpc.SecureOptions{UseTLS: true, ServerRootCAs: [][]byte{ca}},
	}}, sid, tp)
	must(err, "client "+name)
	clients[name] = c
	return c
}

func call(n, fid string, in any) any {
	out, err := node(n).CallView(fid, jsonMarshal(in))
	must(err, fmt.Sprintf("%s.%s", n, fid))
	return out
}

func txID(out any) string { return jsonString(out) }

func finality(tx string, nodes ...string) {
	for _, n := range nodes {
		call(n, "TxFinality", &views1.TxFinality{TxID: tx, Timeout: 90 * time.Second})
	}
}

func issue(typ string, amount uint64, to string) {
	tx := txID(call(bi, "issue", &views.IssueCash{Auditor: auditor, TokenType: token.Type(typ), Quantity: amount, Recipient: []byte(to), RecipientEID: to}))
	finality(tx, to, bi)
	fmt.Printf("issue    %5d %-12s -> %-5s tx %s\n", amount, typ, to, tx[:12])
	reportTx(bi, tx)
}

func transfer(typ string, amount uint64, from, to string) {
	tx := txID(call(from, "transfer", &views.Transfer{Auditor: auditor, Type: token.Type(typ), Amount: amount, Recipient: []byte(to), RecipientEID: to}))
	finality(tx, from, to) // only the two parties: BI may be offline
	fmt.Printf("transfer %5d %-12s %s -> %s tx %s\n", amount, typ, from, to, tx[:12])
	reportTx(from, tx)
}

func swap(from string, giveTyp string, give uint64, to string, getTyp string, get uint64) {
	tx := txID(call(from, "swap", &views.Swap{Auditor: auditor, FromAliceType: token.Type(giveTyp), FromAliceAmount: give, FromBobType: token.Type(getTyp), FromBobAmount: get, Bob: []byte(to)}))
	finality(tx, from, to)
	fmt.Printf("DvP swap %s gives %d %s, %s gives %d %s  tx %s\n", from, give, giveTyp, to, get, getTyp, tx[:12])
	reportTx(from, tx)
}

// reportTx has the initiator report a final transaction to BI. With BI offline the report stays due and
// `driver report` sends it later; the transaction itself is already final either way.
func reportTx(n, tx string) {
	out, err := tryCall(n, "report", &rep.Report{TxID: tx})
	if err != nil {
		fmt.Printf("report   %s tx %s: not delivered (%s), run `driver report` later\n", n, tx[:12], short(err))
		return
	}
	res := map[string]string{}
	jsonUnmarshal(out.([]byte), &res)
	fmt.Printf("report   %s tx %s: BI %s\n", n, tx[:12], res[tx])
	if res[tx] != rep.Recorded && res[tx] != rep.AlreadyRecorded {
		reportFails++
	}
}

var reportFails int

// reportAll has every node report everything it holds, pass after pass, until a pass records nothing new
// (reports must reach BI in causal order). It then lists the transactions BI holds no record of.
func reportAll() {
	for pass := 1; ; pass++ {
		outcome := map[string]string{}
		recorded, undelivered := 0, 0
		for _, n := range append([]string{bi}, banks...) {
			out, err := tryCall(n, "report", &rep.Report{})
			if err != nil {
				fmt.Printf("report   %s: not delivered (%s)\n", n, short(err))
				undelivered++
				continue
			}
			res := map[string]string{}
			jsonUnmarshal(out.([]byte), &res)
			for tx, r := range res {
				if r == rep.Recorded {
					recorded++
				}
				if r == rep.Recorded || r == rep.AlreadyRecorded || outcome[tx] == "" {
					outcome[tx] = r
				}
			}
		}
		fmt.Printf("report   pass %d: %d newly recorded\n", pass, recorded)
		if recorded > 0 {
			time.Sleep(5 * time.Second) // BI stores a recorded transaction's outputs asynchronously, on its finality event
			continue
		}
		missing := 0
		for tx, r := range outcome {
			if r != rep.Recorded && r != rep.AlreadyRecorded {
				missing++
				fmt.Printf("MISSING  tx %s: %s\n", tx[:12], short(fmt.Errorf("%s", r)))
			}
		}
		fmt.Printf("report   BI holds %d of %d transactions known to the nodes\n", len(outcome)-missing, len(outcome))
		if undelivered > 0 {
			must(fmt.Errorf("%d node(s) could not report", undelivered), "report")
		}
		if missing > 0 {
			os.Exit(1)
		}
		return
	}
}

// audited prints BI's audit records, one line per movement.
func audited() {
	var recs []struct {
		TxID         string
		ActionType   int
		SenderEID    string
		RecipientEID string
		TokenType    string
		Amount       uint64
		Status       int
	}
	jsonUnmarshal(call(bi, "audited", struct{}{}).([]byte), &recs)
	for _, r := range recs {
		fmt.Printf("%s  %-8s %-6s -> %-6s %6d %-12s %s\n", r.TxID[:12], []string{"issue", "transfer", "redeem"}[r.ActionType], r.SenderEID, r.RecipientEID, r.Amount, r.TokenType, []string{"unknown", "pending", "confirmed", "deleted", "orphan"}[r.Status])
	}
	fmt.Printf("%d audit records\n", len(recs))
}

func balance(n, typ string) uint64 {
	var last error
	for i := 0; i < 30; i++ {
		out, err := node(n).CallView("balance", jsonMarshal(&views.BalanceQuery{Type: token.Type(typ)}))
		if err == nil {
			b := &views.Balance{}
			jsonUnmarshal(out.([]byte), b)
			q, qerr := token.ToQuantity(b.Quantity, 64)
			if qerr == nil {
				return q.ToBigInt().Uint64()
			}
			last = qerr
		} else {
			last = err
		}
		time.Sleep(2 * time.Second)
	}
	must(last, "balance "+n+" "+typ)
	return 0
}

func expect(n, typ string, want uint64) {
	for i := 0; i < 30; i++ {
		if got := balance(n, typ); got == want {
			fmt.Printf("balance  %-5s %-12s = %d\n", n, typ, got)
			return
		}
		time.Sleep(2 * time.Second)
	}
	must(fmt.Errorf("want %d got %d", want, balance(n, typ)), "balance "+n+" "+typ)
}

// issuerIdentity is the issuer wallet's X.509 identity as listed in the public parameters.
func issuerIdentity() []byte {
	raw, err := os.ReadFile(filepath.Join(live, bi, "core.yaml"))
	must(err, "read issuer core.yaml")
	var cfg struct {
		Token struct {
			TMS map[string]struct {
				Wallets struct {
					Issuers []struct {
						Path string `yaml:"path"`
						Opts struct {
							BCCSP *crypto.BCCSP `yaml:"BCCSP"`
						} `yaml:"opts"`
					} `yaml:"issuers"`
				} `yaml:"wallets"`
			} `yaml:"tms"`
		} `yaml:"token"`
	}
	must(yaml.Unmarshal(raw, &cfg), "parse issuer core.yaml")
	for _, t := range cfg.Token.TMS {
		w := t.Wallets.Issuers[0]
		kmp, _, err := x509.NewKeyManager(w.Path, w.Opts.BCCSP, x509.NewKeyStore(kvs.NewTrackedMemory()))
		must(err, "issuer key manager")
		d, err := kmp.Identity(context.Background(), nil)
		must(err, "issuer identity")
		id, err := identity.WrapWithType(x509.IdentityType, d.Identity)
		must(err, "wrap issuer identity")
		return id
	}
	must(fmt.Errorf("no tms"), "issuer identity")
	return nil
}

// want models the balances every node must hold. It starts from the live balances, so the scenario
// can run on a ledger that already contains earlier transactions, and checks only the changes it makes.
var want = map[string]map[string]uint64{}

func adj(node, typ string, delta int64) { want[node][typ] = uint64(int64(want[node][typ]) + delta) }

func check() {
	for _, n := range []string{"bank2", "bank3", "bank4"} {
		for _, t := range []string{rd, dfabi} {
			expect(n, t, want[n][t])
		}
	}
}

func scenario() {
	for _, n := range []string{"bank2", "bank3", "bank4"} {
		want[n] = map[string]uint64{rd: balance(n, rd), dfabi: balance(n, dfabi)}
	}

	issue(rd, 1000, "bank2")
	adj("bank2", rd, 1000)
	issue(rd, 1000, "bank3")
	adj("bank3", rd, 1000)
	issue(dfabi, 100, "bank3")
	adj("bank3", dfabi, 100)
	check()

	transfer(rd, 100, "bank2", "bank3")
	adj("bank2", rd, -100)
	adj("bank3", rd, 100)
	transfer(dfabi, 10, "bank3", "bank2")
	adj("bank3", dfabi, -10)
	adj("bank2", dfabi, 10)
	check()

	swap("bank2", rd, 200, "bank3", dfabi, 20)
	adj("bank2", rd, -200)
	adj("bank3", rd, 200)
	adj("bank3", dfabi, -20)
	adj("bank2", dfabi, 20)
	check()

	tx := txID(call("bank2", "redeem", &views.Redeem{Auditor: auditor, Issuer: bi, IssuerPublicParamsPublicKey: issuerIdentity(), Type: rd, Amount: 50}))
	finality(tx, bi)
	fmt.Printf("burn       50 %-12s bank2 tx %s\n", rd, tx[:12])
	reportTx("bank2", tx)
	adj("bank2", rd, -50)
	check() // also checks that bank4, which took part in nothing, never moved
	if reportFails > 0 {
		must(fmt.Errorf("%d report(s) refused by BI", reportFails), "reports")
	}
	fmt.Println("SCENARIO OK")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: driver setup-pp|scenario|negative|transfer <from> <to> <type> <amount>|swap <from> <to> <type> <amount> <type> <amount>|balance <node> <type>|report|audited")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "setup-pp":
		pp, err := os.ReadFile(filepath.Join(live, "public-params.bin"))
		must(err, "read public params")
		call(bi, "SetupPublicParams", &ppsetup.SetupPublicParams{Network: "default", Channel: "arma", Namespace: envOr("NAMESPACE", "rd_dfabi"), PublicParamsRaw: pp, Timeout: 2 * time.Minute})
		fmt.Println("public parameters installed")
	case "scenario":
		scenario()
	case "negative":
		negative()
	case "transfer": // transfer <from> <to> <type> <amount>
		var amount uint64
		fmt.Sscan(os.Args[5], &amount)
		transfer(os.Args[4], amount, os.Args[2], os.Args[3])
	case "swap": // swap <from> <to> <type from gives> <amount> <type to gives> <amount>
		var give, get uint64
		fmt.Sscan(os.Args[5], &give)
		fmt.Sscan(os.Args[7], &get)
		swap(os.Args[2], os.Args[4], give, os.Args[3], os.Args[6], get)
	case "balance":
		fmt.Println(balance(os.Args[2], strings.TrimSpace(os.Args[3])))
	case "report": // report [<node> <txid>]
		if len(os.Args) == 4 {
			reportTx(os.Args[2], os.Args[3])
			return
		}
		reportAll()
	case "audited":
		audited()
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func jsonMarshal(v any) []byte {
	raw, err := json.Marshal(v)
	must(err, "marshal")
	return raw
}

func jsonUnmarshal(raw []byte, v any) { must(json.Unmarshal(raw, v), "unmarshal") }

func jsonString(out any) string {
	var s string
	jsonUnmarshal(out.([]byte), &s)
	return s
}

// ---- negative tests ---------------------------------------------------------------------------

var (
	banks = []string{"bank2", "bank3", "bank4"}
	types = []string{rd, dfabi}
	fails int
)

// tryCall is CallView with a deadline and without exiting on error.
func tryCall(n, fid string, in any) (any, error) {
	type res struct {
		out any
		err error
	}
	ch := make(chan res, 1)
	raw := jsonMarshal(in)
	go func() {
		out, err := node(n).CallView(fid, raw)
		ch <- res{out, err}
	}()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-time.After(3 * time.Minute):
		return nil, fmt.Errorf("no answer within 3m")
	}
}

func snapshot() map[string]uint64 {
	m := map[string]uint64{}
	for _, n := range banks {
		for _, t := range types {
			m[n+"/"+t] = balance(n, t)
		}
	}
	return m
}

func diff(a, b map[string]uint64) string {
	var d []string
	for k, v := range a {
		if b[k] != v {
			d = append(d, fmt.Sprintf("%s %d->%d", k, v, b[k]))
		}
	}
	return strings.Join(d, ", ")
}

func short(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 210 {
		s = s[:90] + " ... " + s[len(s)-110:]
	}
	return s
}

func report(name string, ok bool, detail string) {
	st := "PASS"
	if !ok {
		st = "FAIL"
		fails++
	}
	fmt.Printf("%s  %-52s %s\n", st, name, detail)
}

// reject runs f, which must return an error containing one of the wanted substrings (the reason the case
// is about), and checks that no balance moved. The full error goes to negative-errors.log.
func reject(name string, want []string, f func() error) {
	before := snapshot()
	err := f()
	if err != nil {
		if fh, e := os.OpenFile(filepath.Join(filepath.Dir(live), "negative-errors.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); e == nil {
			fmt.Fprintf(fh, "=== %s\n%s\n\n", name, err)
			fh.Close()
		}
	}
	time.Sleep(4 * time.Second) // let pending locks and late commits settle
	d := diff(before, snapshot())
	switch {
	case err == nil:
		report(name, false, "was ACCEPTED, expected a rejection")
	case d != "":
		report(name, false, "rejected but balances changed: "+d)
	case !containsAny(err.Error(), want):
		report(name, false, fmt.Sprintf("rejected, but not for the expected reason %v: %s", want, short(err)))
	default:
		report(name, true, "rejected, balances unchanged: "+short(err))
	}
}

func containsAny(s string, subs []string) bool {
	if len(subs) == 0 {
		return true
	}
	for _, x := range subs {
		if strings.Contains(strings.ToLower(s), strings.ToLower(x)) {
			return true
		}
	}
	return false
}

func waitBalance(n, typ string, want uint64) bool {
	for i := 0; i < 30; i++ {
		if balance(n, typ) == want {
			return true
		}
		time.Sleep(2 * time.Second)
	}
	return false
}

func negative() {
	// Token values are limited by the public parameters' precision (16 bit: 65535). To test "more than I own"
	// without hitting that separate limit, ask for exactly one more than the balance.
	over := func(n, typ string) uint64 {
		b := balance(n, typ)
		if b+1 > 65535 {
			must(fmt.Errorf("%s holds %d %s, one more exceeds the 16-bit token precision", n, b, typ), "negative test setup")
		}
		return b + 1
	}

	// who may do what
	reject("[app level] bank node has no issue view", []string{"no factory found"}, func() error {
		_, err := tryCall("bank2", "issue", &views.IssueCash{Auditor: auditor, TokenType: rd, Quantity: 1000, Recipient: []byte("bank2"), RecipientEID: "bank2"})
		return err
	})
	reject("redeem more than owned", []string{"insufficient funds"}, func() error {
		_, err := tryCall("bank2", "redeem", &views.Redeem{Auditor: auditor, Issuer: bi, IssuerPublicParamsPublicKey: issuerIdentity(), Type: rd, Amount: over("bank2", rd)})
		return err
	})

	// funds and atomicity
	reject("sender without funds", []string{"insufficient funds"}, func() error {
		_, err := tryCall("bank4", "transfer", &views.Transfer{Auditor: auditor, Type: rd, Amount: 10, Recipient: []byte("bank2"), RecipientEID: "bank2"})
		return err
	})
	reject("transfer above balance", []string{"insufficient funds"}, func() error {
		_, err := tryCall("bank2", "transfer", &views.Transfer{Auditor: auditor, Type: rd, Amount: over("bank2", rd), Recipient: []byte("bank3"), RecipientEID: "bank3"})
		return err
	})
	reject("DvP, counterparty lacks the asset (atomic)", []string{"insufficient funds"}, func() error {
		_, err := tryCall("bank2", "swap", &views.Swap{Auditor: auditor, FromAliceType: rd, FromAliceAmount: 10, FromBobType: dfabi, FromBobAmount: over("bank3", dfabi), Bob: []byte("bank3")})
		return err
	})
	reject("DvP, proposer lacks the asset (atomic)", []string{"insufficient funds"}, func() error {
		_, err := tryCall("bank4", "swap", &views.Swap{Auditor: auditor, FromAliceType: rd, FromAliceAmount: 10, FromBobType: dfabi, FromBobAmount: 1, Bob: []byte("bank3")})
		return err
	})

	// identities
	reject("transfer to an unknown party", []string{"failed getting recipient", "failed to get recipient identity"}, func() error {
		_, err := tryCall("bank2", "transfer", &views.Transfer{Auditor: auditor, Type: rd, Amount: 10, Recipient: []byte("bank9"), RecipientEID: "bank9"})
		return err
	})

	// double spend: two concurrent transfers of 60% of the balance each
	before := snapshot()
	amt := before["bank2/"+rd] * 6 / 10
	var wg sync.WaitGroup
	outs := make([]any, 2)
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i], errs[i] = tryCall("bank2", "transfer", &views.Transfer{Auditor: auditor, Type: rd, Amount: amt, Recipient: []byte("bank3"), RecipientEID: "bank3"})
		}(i)
	}
	wg.Wait()
	ok := 0
	for i := 0; i < 2; i++ {
		if errs[i] == nil {
			ok++
			finality(jsonString(outs[i]), "bank2", "bank3")
			reportTx("bank2", jsonString(outs[i]))
		}
	}
	fmt.Printf("INFO  double spend: %d of 2 concurrent transfers of %d RD succeeded\n", ok, amt)
	good := ok <= 1 && waitBalance("bank2", rd, before["bank2/"+rd]-amt*uint64(ok)) && waitBalance("bank3", rd, before["bank3/"+rd]+amt*uint64(ok))
	report("double spend: never more than one of two conflicting transfers", good, fmt.Sprintf("accepted=%d, balances consistent with that", ok))

	// bank4 never took part in anything
	b4rd, b4dfabi := balance("bank4", rd), balance("bank4", dfabi)
	report("bank4 holds nothing after all attempts", b4rd == 0 && b4dfabi == 0, fmt.Sprintf("RD=%d DFABI=%d", b4rd, b4dfabi))

	if fails > 0 {
		fmt.Printf("NEGATIVE FAILED: %d check(s)\n", fails)
		os.Exit(1)
	}
	fmt.Println("NEGATIVE OK")
}
