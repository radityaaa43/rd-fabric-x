package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	rep "github.com/LFDT-Panurus/panurus/integration/token/fungible/rdbi/report"
)

// fakeBI counts what the redeliverer asks of BI: the probe (through BI's gateway) and the report view.
type fakeBI struct {
	probes     int
	probeFails int // the first probeFails probes fail
	reports    []string
	fullPasses int
	refusedAll []string          // txs BI refuses in the startup pass
	allErr     error             // transport failure of the startup pass
	panicOn    string            // deliver panics for this tx
	outcome    map[string]string // per tx; missing = Recorded
	logs       []string
}

func (f *fakeBI) redeliverer(startup bool) *redeliverer {
	return newRedeliverer(redeliverFuncs{
		probe: func() error {
			f.probes++
			if f.probes <= f.probeFails {
				return errors.New("timeout")
			}
			return nil
		},
		deliver: func(tx string) string {
			f.reports = append(f.reports, tx)
			if tx == f.panicOn {
				panic("boom")
			}
			if o, ok := f.outcome[tx]; ok {
				return o
			}
			return rep.Recorded
		},
		deliverAll: func() ([]string, error) { f.fullPasses++; return f.refusedAll, f.allErr },
		logf:       func(format string, a ...any) { f.logs = append(f.logs, fmt.Sprintf(format, a...)) },
	}, startup)
}

// (a) a due report is delivered on the first tick after BI answers, and not retried after.
func TestRedeliverOnFirstTickAfterBIAnswers(t *testing.T) {
	f := &fakeBI{probeFails: 2}
	r := f.redeliverer(false)
	r.note("tx1", "not delivered: dial timeout")
	r.tick()
	r.tick()
	if len(f.reports) != 0 {
		t.Fatalf("report view called while BI is down: %v", f.reports)
	}
	r.tick()
	if !reflect.DeepEqual(f.reports, []string{"tx1"}) {
		t.Fatalf("tick after BI answers: reports = %v, want [tx1]", f.reports)
	}
	probes := f.probes
	r.tick()
	r.tick()
	if len(f.reports) != 1 || f.probes != probes {
		t.Fatalf("after delivery: reports = %v, probes %d -> %d; nothing is due, so no call at all", f.reports, probes, f.probes)
	}
	if got := r.size(); got != 0 {
		t.Fatalf("due set = %d, want 0", got)
	}
}

// (b) with BI down the loop logs one line per tick and nothing else changes.
// (e) with the probe failing the report view is never called (no FSC lock is taken).
func TestRedeliverBIDownLogsOnePerTickAndChangesNothing(t *testing.T) {
	f := &fakeBI{probeFails: 1 << 30}
	r := f.redeliverer(true)
	r.note("a", "not delivered: x")
	r.note("b", "not delivered: x")
	for i := 0; i < 3; i++ {
		r.tick()
	}
	if len(f.reports) != 0 || f.fullPasses != 0 {
		t.Fatalf("report view called with the probe failing: reports %v, full passes %d", f.reports, f.fullPasses)
	}
	if len(f.logs) != 3 {
		t.Fatalf("logs = %d, want one per tick: %q", len(f.logs), f.logs)
	}
	for _, l := range f.logs {
		if !strings.Contains(l, "BI not reachable") {
			t.Fatalf("log line %q does not say BI is not reachable", l)
		}
	}
	if got := r.size(); got != 2 {
		t.Fatalf("due set = %d, want 2 (unchanged)", got)
	}
}

// (c) interval 0 disables the loop.
func TestRedeliverIntervalZeroDisables(t *testing.T) {
	f := &fakeBI{}
	r := f.redeliverer(true)
	r.note("a", "not delivered: x")
	done := make(chan struct{})
	go func() { r.loop(context.Background(), 0); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop with interval 0 did not return")
	}
	if f.probes != 0 || len(f.reports) != 0 {
		t.Fatalf("disabled loop touched BI: probes %d, reports %v", f.probes, f.reports)
	}
}

func TestRedeliverLoopTicksAndStops(t *testing.T) {
	f := &fakeBI{}
	r := f.redeliverer(false)
	r.note("tx1", "not delivered: x")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.loop(ctx, 5*time.Millisecond); close(done) }()
	deadline := time.Now().Add(2 * time.Second)
	for r.size() > 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if r.size() != 0 {
		t.Fatal("loop did not deliver the due report")
	}
}

// The tick stops at the first failure: the rest stays due, nothing is retried inside the tick.
func TestRedeliverStopsAtFirstFailure(t *testing.T) {
	f := &fakeBI{outcome: map[string]string{"b": "not delivered: dial timeout"}}
	r := f.redeliverer(false)
	r.note("b", "not delivered: x")
	r.note("a", "not delivered: x")
	r.tick()
	if !reflect.DeepEqual(f.reports, []string{"b"}) {
		t.Fatalf("reports = %v, want only [b] (arrival order, stop at the first transport failure)", f.reports)
	}
	if got := r.size(); got != 2 {
		t.Fatalf("due set = %d, want 2", got)
	}
}

// A refusal by BI (causal order) is not a delivery: the tx stays due, "already recorded" and "recorded" clear it.
func TestRedeliverOutcomes(t *testing.T) {
	f := &fakeBI{outcome: map[string]string{"a": rep.AlreadyRecorded, "b": "missing inputs of an earlier report"}}
	r := f.redeliverer(false)
	r.note("a", "not delivered: x")
	r.note("b", "not delivered: x")
	r.tick()
	if got := r.size(); got != 1 {
		t.Fatalf("due set = %d, want 1 (b refused)", got)
	}
}

// note: only a delivery clears or avoids the due state.
func TestRedeliverNote(t *testing.T) {
	r := (&fakeBI{}).redeliverer(false)
	r.note("ok1", rep.Recorded)
	r.note("ok2", rep.AlreadyRecorded)
	if r.size() != 0 {
		t.Fatalf("a delivered report was added to the due set")
	}
	r.note("bad1", "not delivered: x")
	r.note("bad2", "refused")
	if r.size() != 2 {
		t.Fatalf("due set = %d, want 2", r.size())
	}
	r.note("bad1", rep.Recorded)
	if r.size() != 1 {
		t.Fatalf("a manual delivery must clear the tx: due set = %d, want 1", r.size())
	}
}

// At startup one full pass runs, gated by the same probe; a restart does not lose reports.
func TestRedeliverStartupPassIsGated(t *testing.T) {
	f := &fakeBI{probeFails: 1}
	r := f.redeliverer(true)
	r.tick()
	if f.fullPasses != 0 {
		t.Fatalf("startup pass ran with the probe failing")
	}
	r.tick()
	if f.fullPasses != 1 {
		t.Fatalf("startup pass after BI answers: %d, want 1", f.fullPasses)
	}
	probes := f.probes
	r.tick()
	if f.fullPasses != 1 || f.probes != probes {
		t.Fatalf("startup pass must run once: passes %d, probes %d -> %d", f.fullPasses, probes, f.probes)
	}
}

func TestRedeliverInterval(t *testing.T) {
	for in, want := range map[string]time.Duration{"": time.Minute, "0": 0, "30s": 30 * time.Second, "2m": 2 * time.Minute} {
		got, err := redeliverInterval(in)
		if err != nil || got != want {
			t.Errorf("redeliverInterval(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"abc", "-1s", "60"} {
		if _, err := redeliverInterval(in); err == nil {
			t.Errorf("redeliverInterval(%q): want an error", in)
		}
	}
}

// F1: a refusal by BI (it has the request, it just wants an earlier report first) must not block the txs behind it;
// only a transport failure stops the tick.
func TestRedeliverContinuesPastRefusal(t *testing.T) {
	f := &fakeBI{outcome: map[string]string{"a": "missing inputs of an earlier report"}}
	r := f.redeliverer(false)
	r.note("a", "not delivered: x")
	r.note("b", "not delivered: x")
	r.tick()
	if !reflect.DeepEqual(f.reports, []string{"a", "b"}) {
		t.Fatalf("reports = %v, want [a b]: a refusal must not stop the tick", f.reports)
	}
	if got := r.size(); got != 1 {
		t.Fatalf("due set = %d, want 1 (only a stays due)", got)
	}
}

// F2: reports BI refuses in the startup pass become due; the pass is done and the due loop still runs.
func TestRedeliverStartupRefusedBecomeDue(t *testing.T) {
	f := &fakeBI{refusedAll: []string{"x"}}
	r := f.redeliverer(true)
	r.tick()
	if f.fullPasses != 1 || !reflect.DeepEqual(f.reports, []string{"x"}) {
		t.Fatalf("passes %d, reports %v: the refused tx must be sent from the due set in the same tick", f.fullPasses, f.reports)
	}
	r.tick()
	if f.fullPasses != 1 {
		t.Fatalf("startup pass repeated: %d", f.fullPasses)
	}
}

// F2: a transport failure of the startup pass keeps it pending and sends nothing else.
func TestRedeliverStartupTransportFailureRetries(t *testing.T) {
	f := &fakeBI{allErr: errors.New("not delivered: timeout")}
	r := f.redeliverer(true)
	r.note("a", "not delivered: x")
	r.tick()
	r.tick()
	if f.fullPasses != 2 || len(f.reports) != 0 {
		t.Fatalf("passes %d, reports %v; want the pass retried and no due tx sent", f.fullPasses, f.reports)
	}
}

// F3: the report view's answer is checked, not asserted blindly.
func TestRedeliverReportOutcomes(t *testing.T) {
	if _, err := reportOutcomes(nil); err == nil {
		t.Error("nil answer: want an error")
	}
	if _, err := reportOutcomes(42); err == nil {
		t.Error("non-bytes answer: want an error")
	}
	if _, err := reportOutcomes([]byte("not json")); err == nil {
		t.Error("bad json: want an error")
	}
	res, err := reportOutcomes([]byte(`{"tx1":"recorded"}`))
	if err != nil || res["tx1"] != rep.Recorded {
		t.Errorf("got %v, %v", res, err)
	}
}

// F3: a panic in a tick must not kill the process (the loop is a goroutine without a request to recover it).
func TestRedeliverTickPanicIsContained(t *testing.T) {
	f := &fakeBI{panicOn: "a"}
	r := f.redeliverer(false)
	r.note("a", "not delivered: x")
	r.safeTick()
	found := false
	for _, l := range f.logs {
		found = found || strings.Contains(l, "panic")
	}
	if !found {
		t.Fatalf("no panic line in logs: %q", f.logs)
	}
}

// F5: a disabled loop keeps no state.
func TestRedeliverDisabledKeepsNoState(t *testing.T) {
	r := (&fakeBI{}).redeliverer(false)
	r.disable()
	r.note("a", "not delivered: x")
	if r.size() != 0 {
		t.Fatalf("disabled: due set = %d, want 0", r.size())
	}
}

// F6: run() adds a transaction whose report did not reach BI to the global due set.
func TestRunNotesUndeliveredReport(t *testing.T) {
	old := pending
	pending = newRedeliverer(redeliverFuncs{}, false)
	t.Cleanup(func() { pending = old })
	setup(t, "bank2", 200, "[]", "report") // the report view fails: BI unreachable
	if code, out := post(`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"7"}`); code != 200 || !strings.Contains(out, "not delivered") {
		t.Fatalf("got %d %s", code, out)
	}
	if pending.size() != 1 {
		t.Fatalf("due set = %d, want 1", pending.size())
	}
}

// F6: a delivered report does not become due, and `op: report` clears a due tx.
func TestReportOpClearsDue(t *testing.T) {
	old := pending
	pending = newRedeliverer(redeliverFuncs{}, false)
	t.Cleanup(func() { pending = old })
	setup(t, "bank2", 200, "[]", "")
	post(`{"op":"transfer","from":"bank2","to":"bank3","type":"RD","amount":"7"}`)
	if pending.size() != 0 {
		t.Fatalf("a delivered report was added: due set = %d", pending.size())
	}
	pending.note("tx1", "not delivered: x")
	if code, out := post(`{"op":"report","txid":"tx1"}`); code != 200 || !strings.Contains(out, "recorded") {
		t.Fatalf("got %d %s", code, out)
	}
	if pending.size() != 0 {
		t.Fatalf("op report did not clear the tx: due set = %d", pending.size())
	}
}

// Reports go out in arrival order, not in tx-id order: BI needs earlier reports first (causal order).
func TestRedeliverArrivalOrder(t *testing.T) {
	f := &fakeBI{}
	r := f.redeliverer(false)
	for _, tx := range []string{"c", "a", "b"} {
		r.note(tx, "not delivered: x")
	}
	r.tick()
	if !reflect.DeepEqual(f.reports, []string{"c", "a", "b"}) {
		t.Fatalf("reports = %v, want [c a b]", f.reports)
	}
}

// A report BI keeps refusing is retried a bounded number of times, then dropped (op: report still retries it).
func TestRedeliverGivesUpAfterRepeatedRefusals(t *testing.T) {
	f := &fakeBI{outcome: map[string]string{"a": "token request does not match"}}
	r := f.redeliverer(false)
	r.note("a", "not delivered: x")
	for i := 0; i < maxRefusals+3; i++ {
		r.tick()
	}
	if len(f.reports) != maxRefusals {
		t.Fatalf("deliver calls = %d, want %d", len(f.reports), maxRefusals)
	}
	if r.size() != 0 {
		t.Fatalf("due set = %d, want 0 after giving up", r.size())
	}
	found := false
	for _, l := range f.logs {
		found = found || strings.Contains(l, "giving up")
	}
	if !found {
		t.Fatalf("no 'giving up' line: %q", f.logs)
	}
}
