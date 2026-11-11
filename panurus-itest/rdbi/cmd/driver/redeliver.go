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
	probe      func() error           // nil when BI answers through its gateway
	deliver    func(tx string) string // the `op: report` path: BI's outcome or "not delivered: ..."
	deliverAll func() error           // the startup pass: the report view with an empty TxID
	logf       func(string, ...any)
}

type redeliverer struct {
	f       redeliverFuncs
	mu      sync.Mutex
	due     map[string]struct{}
	startup bool // the startup pass has not run yet
}

func newRedeliverer(f redeliverFuncs, startup bool) *redeliverer {
	return &redeliverer{f: f, due: map[string]struct{}{}, startup: startup}
}

func delivered(outcome string) bool { return outcome == rep.Recorded || outcome == rep.AlreadyRecorded }

// note records BI's outcome for a transaction: a delivery clears it, anything else makes it due.
func (r *redeliverer) note(tx, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if delivered(outcome) {
		delete(r.due, tx)
	} else {
		r.due[tx] = struct{}{}
	}
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
	ids := make([]string, 0, len(r.due))
	for tx := range r.due {
		ids = append(ids, tx)
	}
	r.mu.Unlock()
	if !startup && len(ids) == 0 {
		return
	}
	sort.Strings(ids)
	if err := r.f.probe(); err != nil {
		r.f.logf("redeliver: BI not reachable (%v), %d due, skipping tick", err, len(ids))
		return
	}
	if startup {
		if err := r.f.deliverAll(); err != nil {
			r.f.logf("redeliver: startup pass: %v", err)
			return
		}
		r.mu.Lock()
		r.startup = false
		r.mu.Unlock()
		r.f.logf("redeliver: startup pass done")
	}
	for _, tx := range ids {
		out := r.f.deliver(tx)
		r.note(tx, out)
		if !delivered(out) {
			r.f.logf("redeliver %.12s: %s, stopping tick", tx, out)
			return
		}
		r.f.logf("redeliver %.12s: %s", tx, out)
	}
}

// loop ticks every `every` (and once at once) until ctx ends; every <= 0 disables it.
func (r *redeliverer) loop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	r.tick()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick()
		}
	}
}

// pending is this process's due set; serve() replaces it with the real effects.
var pending = newRedeliverer(redeliverFuncs{}, false)

func newRealRedeliverer(startup bool) *redeliverer {
	return newRedeliverer(redeliverFuncs{
		probe:   probeBI,
		deliver: deliver,
		deliverAll: func() error {
			o, err := tryCall(party, "report", &rep.Report{})
			if err != nil {
				return fmt.Errorf("not delivered: %s", short(err))
			}
			res := map[string]string{}
			jsonUnmarshal(o.([]byte), &res)
			refused := 0
			for _, out := range res {
				if !delivered(out) {
					refused++
				}
			}
			if refused > 0 {
				return fmt.Errorf("BI refused %d of %d reports", refused, len(res))
			}
			return nil
		},
		logf: func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}, startup)
}

// probeBI asks BI's own gateway for a read (usage), which makes fx-gw-1 call BI's node: 200 means BI answers.
// The client shares the mTLS transport of the peer client (precheck) and has its own, shorter timeout.
func probeBI() error {
	body, _ := json.Marshal(map[string]string{"op": "usage", "type": "RD", "since": time.Now().UTC().Format(time.RFC3339)})
	c := &http.Client{Timeout: probeTimeout, Transport: peer.Transport}
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
