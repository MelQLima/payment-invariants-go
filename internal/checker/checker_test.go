package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI is a minimal payment API. With ignoreIdempotency it has the classic
// bug (a new payment per request): the checker must catch it.
type fakeAPI struct {
	ignoreIdempotency bool
	mu                sync.Mutex
	seq               atomic.Int64
	byKey             map[string]string
	payments          map[string]*Payment
}

func newFake(ignore bool) *fakeAPI {
	return &fakeAPI{ignoreIdempotency: ignore, byKey: map[string]string{}, payments: map[string]*Payment{}}
}

func (f *fakeAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {})
	mux.HandleFunc("POST /v1/tokens", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"tok_x","bin":"411111","last4":"1111"}`))
	})
	mux.HandleFunc("POST /v1/payments", func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		f.mu.Lock()
		defer f.mu.Unlock()
		if id, ok := f.byKey[key]; ok && !f.ignoreIdempotency {
			_ = json.NewEncoder(w).Encode(f.payments[id])
			return
		}
		id := fmt.Sprintf("pay_%d", f.seq.Add(1))
		p := &Payment{ID: id, Status: "captured", Attempts: []Attempt{{Provider: "a", Approved: true}}}
		f.byKey[key], f.payments[id] = id, p
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	})
	mux.HandleFunc("GET /v1/payments/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if p, ok := f.payments[r.PathValue("id")]; ok {
			_ = json.NewEncoder(w).Encode(p)
			return
		}
		http.NotFound(w, r)
	})
	return mux
}

func envFor(srv *httptest.Server) *Env {
	return &Env{C: NewClient(srv.URL, 64), Concurrency: 10, Run: "test", Secrets: map[string]string{}}
}

func TestIdempotencyInvariantAcceptsCorrectAPI(t *testing.T) {
	srv := httptest.NewServer(newFake(false).handler())
	defer srv.Close()
	if ok, detail := idemConcurrent(context.Background(), envFor(srv)); !ok {
		t.Fatalf("a correct API must pass: %s", detail)
	}
}

func TestIdempotencyInvariantCatchesDoubleCharge(t *testing.T) {
	srv := httptest.NewServer(newFake(true).handler())
	defer srv.Close()
	ok, detail := idemConcurrent(context.Background(), envFor(srv))
	if ok {
		t.Fatalf("an API that ignores Idempotency-Key must fail the invariant: %s", detail)
	}
	if !strings.Contains(detail, "distinct payment id") {
		t.Fatalf("detail should say why: %s", detail)
	}
}

func TestSignWebhookIsStableAndBodyBound(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0)
	a := SignWebhook("s3cret", ts, []byte(`{"id":"1"}`))
	if a != SignWebhook("s3cret", ts, []byte(`{"id":"1"}`)) {
		t.Fatal("signature must be deterministic")
	}
	if a == SignWebhook("s3cret", ts, []byte(`{"id":"2"}`)) {
		t.Fatal("signature must depend on the body")
	}
	if a == SignWebhook("other", ts, []byte(`{"id":"1"}`)) {
		t.Fatal("signature must depend on the secret")
	}
	if !strings.HasPrefix(a, "t=1700000000,v1=") {
		t.Fatalf("unexpected header format: %s", a)
	}
}

func TestPercentile(t *testing.T) {
	d := []time.Duration{5, 1, 4, 2, 3}
	if got := percentile(d, 0.5); got != 3 {
		t.Fatalf("p50 = %v", got)
	}
	if got := percentile(d, 0.95); got != 4 {
		t.Fatalf("p95 = %v", got)
	}
	if percentile(nil, 0.5) != 0 {
		t.Fatal("empty input must yield 0")
	}
}

func TestReportFailedAndExitSemantics(t *testing.T) {
	r := Report{Results: []Result{{Pass: true}, {Pass: false}, {Pass: false}}}
	if r.Failed() != 2 {
		t.Fatalf("Failed() = %d", r.Failed())
	}
	var sb strings.Builder
	r.WriteText(&sb, false)
	if !strings.Contains(sb.String(), "2 of 3 invariants VIOLATED") {
		t.Fatalf("summary missing: %s", sb.String())
	}
}

func TestRunRefusesUnhealthyTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	if _, err := Run(context.Background(), Options{Target: srv.URL}); err == nil {
		t.Fatal("expected an error for an unhealthy target")
	}
}
