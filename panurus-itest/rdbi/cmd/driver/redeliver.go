package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	rep "github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
)

// Redelivery of reports to BI (fabric-x/opa/DESIGN.md section 5, report-to-BI). run() sends a transaction's report to
// BI after finality; when BI is down it answers "not delivered" and the transaction becomes due here. A loop in the
// serving process (the fxapi container of fx-gw-N) delivers the due reports once BI answers again.
//
// The due set is in memory. A restart loses it, so the first pass after startup sends everything the node holds
// (the same `report` view with an empty TxID that `driver report` uses; BI answers "already recorded" for known ones).
//
// Gate: a dial to a dead BI holds the FSC node's connection lock for the OS connect timeout (~127 s,
// fsc platform/view/services/comm/host/websocket/ws/multiplexed_provider.go:157-162) and queues every other flow of the
// bank behind it. So the report view is never called blindly: BI is probed first through its gateway (fx-gw-1,
// op usage, mTLS, 3 s timeout) and the report view runs only when the probe answers 200. The probe's latency with BI
// down is [unverified] until the live run.
const (
	envRedeliver     = "RDBI_REDELIVER_INTERVAL" // Go duration, "0" disables
	defaultRedeliver = time.Minute
	probeTimeout     = 3 * time.Second
)

// redeliverInterval parses RDBI_REDELIVER_INTERVAL: empty = 60 s, "0" = off.
func redeliverInterval(s string) (time.Duration, error) {
	if s == "" {
		return defaultRedeliver, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", envRedeliver, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: negative interval %q", envRedeliver, s)
	}
	return d, nil
}

// redeliverFuncs are the effects of the loop, so a test can replace BI.
type redeliverFuncs struct {
	probe      func() error             // nil when BI answers through its gateway
	deliver    func(tx string) string   // the `op: report` path: BI's outcome or "not delivered: ..."
	deliverAll func() ([]string, error) // the startup pass: the report view with an empty TxID
	logf       func(string, ...any)
}

type redeliverer struct {
	f       redeliverFuncs
	mu      sync.Mutex
	due     map[string]*dueTx
	seq     uint64 // arrival order: reports must reach BI in causal order, and arrival is the best proxy we have
	startup bool   // the startup pass has not run yet
	off     bool   // the loop is disabled: keep no state
}

func newRedeliverer(f redeliverFuncs, startup bool) *redeliverer {
	return &redeliverer{f: f, due: map[string]*dueTx{}, startup: startup}
}

// dueTx is one transaction whose report BI has not recorded yet.
type dueTx struct {
	seq     uint64
	refused int // times BI answered but did not record it
}

// maxRefusals bounds the retries of a report BI keeps refusing. Why not drop at the first refusal: BI needs the
// reports in causal order ("a refused report is simply sent again later", rdbi/report/report.go:11-13), so a report
// that goes out before its prerequisite is refused only transiently, and after an outage dependent reports (a
// transfer that spends the change of the one before) are the normal case. A forged or altered report is refused
// every time: after maxRefusals tries it is dropped, and only `op: report` retries it. Reports are sent in arrival
// order, so the prerequisite usually goes first.
const maxRefusals = 5

func delivered(outcome string) bool { return outcome == rep.Recorded || outcome == rep.AlreadyRecorded }

// note records BI's outcome for a transaction: a delivery clears it, anything else makes it due.
func (r *redeliverer) note(tx, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.off {
		return
	}
	if delivered(outcome) {
		delete(r.due, tx)
	} else if r.due[tx] == nil {
		r.seq++
		r.due[tx] = &dueTx{seq: r.seq}
	}
}

// disable stops the due set from growing when the loop is off (RDBI_REDELIVER_INTERVAL=0).
func (r *redeliverer) disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.off = true
	r.due = map[string]*dueTx{}
}

func (r *redeliverer) size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.due)
}

// tick runs one pass: nothing due and no startup pass pending means no call at all; BI not reachable means one log
// line; otherwise each due transaction is delivered once, in order, and the tick stops at the first failure.
func (r *redeliverer) tick() {
	r.mu.Lock()
	startup := r.startup
	r.mu.Unlock()
	ids := r.dueIDs()
	if !startup && len(ids) == 0 {
		return
	}
	if err := r.f.probe(); err != nil {
		r.f.logf("redeliver: BI not reachable (%v), %d due, skipping tick", err, len(ids))
		return
	}
	if startup {
		refused, err := r.f.deliverAll()
		if err != nil {
			r.f.logf("redeliver: startup pass: %v", err)
			return
		}
		r.mu.Lock()
		r.startup = false
		r.mu.Unlock()
		r.f.logf("redeliver: startup pass done, %d refused by BI (kept due)", len(refused))
		sort.Strings(refused)
		for _, tx := range refused {
			r.note(tx, "refused")
		}
		ids = r.dueIDs()
	}
	for {
		ok, refused := 0, []string{}
		for _, tx := range ids {
			out := r.f.deliver(tx)
			r.note(tx, out)
			switch {
			case delivered(out):
				ok++
				r.f.logf("redeliver %.12s: %s", tx, out)
			case strings.HasPrefix(out, "not delivered"): // transport failure: BI is gone again, stop this tick
				r.f.logf("redeliver %.12s: %s, stopping tick", tx, out)
				return
			default: // BI answered but did not record it (e.g. an earlier report is missing)
				refused = append(refused, tx)
				r.f.logf("redeliver %.12s: refused by BI (%s)", tx, out)
			}
		}
		if len(refused) == 0 {
			return
		}
		if ok > 0 { // progress: an earlier report may now be in, so the refused ones get another pass in this tick
			ids = refused
			continue
		}
		// a pass without progress: only now does a refusal count, once per tx and tick
		for _, tx := range refused {
			if n, dropped := r.refuse(tx); dropped {
				r.f.logf("redeliver %.12s: refused by BI %d times, giving up; `op: report` retries it", tx, n)
			} else {
				r.f.logf("redeliver %.12s: refusal %d of %d", tx, n, maxRefusals)
			}
		}
		return
	}
}

func (r *redeliverer) dueIDs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.due))
	for tx := range r.due {
		ids = append(ids, tx)
	}
	sort.Slice(ids, func(i, j int) bool { return r.due[ids[i]].seq < r.due[ids[j]].seq })
	return ids
}

// refuse counts a refusal by BI; it reports whether the tx was dropped for good.
func (r *redeliverer) refuse(tx string) (n int, dropped bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.due[tx]
	if e == nil {
		return 0, false
	}
	e.refused++
	if e.refused >= maxRefusals {
		delete(r.due, tx)
		return e.refused, true
	}
	return e.refused, false
}

// safeTick contains a panic: the loop is a goroutine without a request to recover it, and a panic would kill fxapi.
func (r *redeliverer) safeTick() {
	defer func() {
		if p := recover(); p != nil {
			r.f.logf("redeliver: panic in tick: %v", p)
		}
	}()
	r.tick()
}

// loop ticks every `every` (and once at once) until ctx ends; every <= 0 disables it.
func (r *redeliverer) loop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	r.safeTick()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.safeTick()
		}
	}
}

// pending is this process's due set; serve() replaces it with the real effects.
var pending = newRedeliverer(redeliverFuncs{}, false)

func newRealRedeliverer(startup bool) *redeliverer {
	return newRedeliverer(redeliverFuncs{
		probe:   probeBI,
		deliver: deliver,
		deliverAll: func() ([]string, error) {
			o, err := tryCall(party, "report", &rep.Report{})
			if err != nil {
				return nil, fmt.Errorf("not delivered: %s", short(err))
			}
			res, err := reportOutcomes(o)
			if err != nil {
				return nil, fmt.Errorf("not delivered: %v", err)
			}
			var refused []string
			for tx, out := range res {
				if !delivered(out) {
					refused = append(refused, tx)
				}
			}
			return refused, nil
		},
		logf: func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}, startup)
}

// probeBI asks BI's own gateway for a read (usage), which makes fx-gw-1 call BI's node: 200 means BI answers.
// The client shares the mTLS transport of BI's peer client (org 1's root only) and has its own, shorter timeout.
func probeBI() error {
	body, _ := json.Marshal(map[string]string{"op": "usage", "type": "RD", "since": time.Now().UTC().Format(time.RFC3339)})
	c := &http.Client{Timeout: probeTimeout, Transport: peerFor(gwOf[bi]).Transport}
	resp, err := c.Post(fmt.Sprintf(peerURL, gwOf[bi]), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// reportOutcomes decodes the report view's answer (per tx: BI's outcome) without trusting its type.
func reportOutcomes(o any) (map[string]string, error) {
	b, ok := o.([]byte)
	if !ok {
		return nil, fmt.Errorf("report view returned %T, want JSON bytes", o)
	}
	res := map[string]string{}
	if err := json.Unmarshal(b, &res); err != nil {
		return nil, fmt.Errorf("report view answer: %w", err)
	}
	return res, nil
}

// reportOutcome is BI's outcome for tx in the report view's answer. A tx absent from the answer was not delivered
// (an empty tx, the "everything" call of `op: report`, has no single outcome and yields "").
func reportOutcome(o any, tx string) (string, error) {
	res, err := reportOutcomes(o)
	if err != nil || tx == "" {
		return "", err
	}
	out, ok := res[tx]
	if !ok {
		return "", fmt.Errorf("tx missing from BI reply")
	}
	return out, nil
}
