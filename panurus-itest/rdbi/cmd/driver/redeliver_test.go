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
			if o, ok := f.outcome[tx]; ok {
				return o
			}
			return rep.Recorded
		},
		deliverAll: func() error { f.fullPasses++; return nil },
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
	f := &fakeBI{outcome: map[string]string{"a": "not delivered: dial timeout"}}
	r := f.redeliverer(false)
	r.note("b", "not delivered: x")
	r.note("a", "not delivered: x")
	r.tick()
	if !reflect.DeepEqual(f.reports, []string{"a"}) {
		t.Fatalf("reports = %v, want only [a] (sorted, stop at the first failure)", f.reports)
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
