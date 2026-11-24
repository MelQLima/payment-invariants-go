package checker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Test card numbers (Luhn-valid, never real).
const (
	panVisa = "4111111111111111"
	panLeak = "4000056655665556"
)

type scenario struct {
	id, name, claim string
	run             func(ctx context.Context, e *Env) (bool, string)
}

// Options configures a run.
type Options struct {
	Target      string
	Concurrency int
	Secrets     map[string]string
	LogFile     string // optional: server log scanned for the PAN
	Only        string // optional: run a single invariant by id
}

// Run executes every invariant and returns the report.
func Run(ctx context.Context, o Options) (Report, error) {
	if o.Concurrency <= 0 {
		o.Concurrency = 20
	}
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	e := &Env{C: NewClient(o.Target, o.Concurrency+60), Secrets: o.Secrets, Concurrency: o.Concurrency, Run: hex.EncodeToString(b)}
	rep := Report{Target: o.Target, Run: e.Run}
	if r, err := e.C.Do(ctx, "GET", "/healthz", nil, nil); err != nil || r.Status != http.StatusOK {
		return rep, fmt.Errorf("target %s is not healthy (is the API running?): %v", o.Target, err)
	}
	for _, s := range all(o) {
		if o.Only != "" && !strings.EqualFold(o.Only, s.id) {
			continue
		}
		start := time.Now()
		pass, detail := s.run(ctx, e)
		rep.Results = append(rep.Results, Result{ID: s.id, Name: s.name, Claim: s.claim, Pass: pass, Detail: detail, Took: time.Since(start)})
	}
	return rep, nil
}

func all(o Options) []scenario {
	return []scenario{
		{"I1", "idempotency-concurrent", "50 identical concurrent requests create exactly one payment and the acquirer is called once", idemConcurrent},
		{"I2", "idempotency-contract", "same key + same body replays the response; same key + different body is rejected with 422", idemContract},
		{"I3", "distinct-keys-under-load", "200 distinct requests create 200 distinct, captured payments", distinctKeys},
		{"I4", "decline-routing", "hard and insufficient-funds declines never cascade to another acquirer; technical failures do", declineRouting},
		{"I5", "refund-bound", "20 concurrent refunds never move more money than was captured, and every 2xx moved money", refundBound},
		{"I6", "webhook-authenticity", "forged, tampered, stale and unknown-provider webhooks change nothing", webhookAuthenticity},
		{"I7", "webhook-resend", "a provider that resends the same event gets 200 each time and the event applies once", webhookResend},
		{"I8", "webhook-parallel-duplicates", "the same event delivered 40 times in parallel (8 rounds) applies once and never returns 5xx", webhookParallel},
		{"I9", "pan-never-leaks", "the card number appears in no response, metric" + logSuffix(o) + "; only BIN and last4 are exposed", func(ctx context.Context, e *Env) (bool, string) { return panNeverLeaks(ctx, e, o.LogFile) }},
		{"I10", "client-abort-retry", "a client that times out and retries never causes a second approval", clientAbortRetry},
		{"I11", "aborts-dont-poison-providers", "clients that disconnect mid-request must not open the circuit breakers: the next customer still gets paid", abortsDontPoison},
	}
}

func logSuffix(o Options) string {
	if o.LogFile != "" {
		return " or log line"
	}
	return ""
}

func (e *Env) key(parts ...string) string { return "chk-" + e.Run + "-" + strings.Join(parts, "-") }

func fanOut(n, conc int, fn func(i int)) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

func (e *Env) captured(ctx context.Context, tag string, amount int64) (*Payment, error) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return nil, err
	}
	_, p, err := e.Pay(ctx, e.key(tag), PayReq{"m-chk", amount, "BRL", tok, true})
	if err != nil || p == nil || p.Status != "captured" {
		return nil, fmt.Errorf("setup payment %s not captured (err=%v)", tag, err)
	}
	return p, nil
}

func idemConcurrent(ctx context.Context, e *Env) (bool, string) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	const n = 50
	key := e.key("idem-conc")
	req := PayReq{"m-chk", 12500, "BRL", tok, true}
	var mu sync.Mutex
	codes := map[int]int{}
	ids := map[string]int{}
	errs := 0
	fanOut(n, n, func(int) {
		r, p, err := e.Pay(ctx, key, req)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			errs++
			return
		}
		codes[r.Status]++
		if p != nil {
			ids[p.ID]++
		}
	})
	unexpected := 0
	for c, k := range codes {
		if (c < 200 || c > 299) && c != http.StatusConflict {
			unexpected += k
		}
	}
	detail := fmt.Sprintf("%d requests -> %d distinct payment id(s); responses %v", n, len(ids), codes)
	if errs > 0 || unexpected > 0 || len(ids) != 1 {
		return false, detail + fmt.Sprintf("; transport errors %d, unexpected statuses %d", errs, unexpected)
	}
	for id := range ids {
		p, err := e.Get(ctx, id)
		if err != nil {
			return false, err.Error()
		}
		if len(p.Attempts) != 1 {
			return false, detail + fmt.Sprintf("; acquirer was called %d times", len(p.Attempts))
		}
		return true, detail + "; acquirer called once"
	}
	return false, detail
}

func idemContract(ctx context.Context, e *Env) (bool, string) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	key := e.key("idem-contract")
	_, p1, err := e.Pay(ctx, key, PayReq{"m-chk", 12600, "BRL", tok, true})
	if err != nil || p1 == nil {
		return false, fmt.Sprintf("first call failed: %v", err)
	}
	_, p2, _ := e.Pay(ctx, key, PayReq{"m-chk", 12600, "BRL", tok, true})
	r3, _, _ := e.Pay(ctx, key, PayReq{"m-chk", 99900, "BRL", tok, true})
	replay := p2 != nil && p2.ID == p1.ID
	rejected := r3.Status == http.StatusUnprocessableEntity
	detail := fmt.Sprintf("replay returned same id: %v; different body answered HTTP %d (want 422)", replay, r3.Status)
	return replay && rejected, detail
}

func clientAbortRetry(ctx context.Context, e *Env) (bool, string) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	const n = 12
	var mu sync.Mutex
	doubleApproved, inconsistent, failed, unavailable := 0, 0, 0, 0
	statuses := map[string]int{}
	fanOut(n, e.Concurrency, func(i int) {
		key := e.key("abort", fmt.Sprint(i))
		req := PayReq{"m-chk", 14000 + int64(i)*100, "BRL", tok, true}
		short, cancel := context.WithTimeout(ctx, 15*time.Millisecond) // client gives up mid-flight
		_, _, _ = e.Pay(short, key, req)
		cancel()
		time.Sleep(250 * time.Millisecond)
		var first *Payment
		last := 0
		for try := 0; try < 10 && first == nil; try++ {
			r, p, err := e.Pay(ctx, key, req)
			if err == nil && p != nil {
				first = p
				break
			}
			last = r.Status
			time.Sleep(100 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		if first == nil {
			if last == http.StatusServiceUnavailable {
				unavailable++ // judged by I11
			} else {
				failed++
			}
			return
		}
		_, again, _ := e.Pay(ctx, key, req)
		if again == nil || again.ID != first.ID {
			inconsistent++
		}
		p, err := e.Get(ctx, first.ID)
		if err != nil {
			failed++
			return
		}
		ok := 0
		for _, a := range p.Attempts {
			if a.Approved {
				ok++
			}
		}
		if ok > 1 {
			doubleApproved++
		}
		statuses[p.Status]++
	})
	detail := fmt.Sprintf("%d aborted+retried -> final statuses %v, %d got 503 (see I11); double approvals %d, id changed on replay %d, unresolved %d", n, statuses, unavailable, doubleApproved, inconsistent, failed)
	return doubleApproved == 0 && inconsistent == 0 && failed == 0, detail
}

func distinctKeys(ctx context.Context, e *Env) (bool, string) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	const n = 200
	var mu sync.Mutex
	ids := map[string]bool{}
	var durs []time.Duration
	notCaptured, errs := 0, 0
	fanOut(n, e.Concurrency, func(i int) {
		r, p, err := e.Pay(ctx, e.key("load", fmt.Sprint(i)), PayReq{"m-chk", 10000 + int64(i%50)*100, "BRL", tok, true})
		mu.Lock()
		defer mu.Unlock()
		if err != nil || p == nil {
			errs++
			return
		}
		ids[p.ID] = true
		durs = append(durs, r.Dur)
		if p.Status != "captured" {
			notCaptured++
		}
	})
	detail := fmt.Sprintf("%d requests at concurrency %d -> %d distinct ids, p50 %d ms, p95 %d ms, errors %d, not captured %d",
		n, e.Concurrency, len(ids), percentile(durs, .5).Milliseconds(), percentile(durs, .95).Milliseconds(), errs, notCaptured)
	return len(ids) == n && errs == 0 && notCaptured == 0, detail
}

func declineRouting(ctx context.Context, e *Env) (bool, string) {
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	try := func(tag string, amount int64) *Payment {
		_, p, _ := e.Pay(ctx, e.key("decl", tag), PayReq{"m-chk", amount, "BRL", tok, true})
		return p
	}
	stolen, funds, tech := try("43", 10043), try("51", 10051), try("91", 10091)
	if stolen == nil || funds == nil || tech == nil {
		return false, "could not create decline scenarios"
	}
	providers := map[string]bool{}
	for _, a := range tech.Attempts {
		providers[a.Provider] = true
	}
	okHard := stolen.Status == "declined" && len(stolen.Attempts) == 1
	okFunds := funds.Status == "declined" && len(funds.Attempts) == 1
	okTech := len(tech.Attempts) >= 2 && len(providers) >= 2
	detail := fmt.Sprintf("stolen card (43): %d attempt(s); insufficient funds (51): %d attempt(s); issuer unavailable (91): %d attempts over %d acquirers",
		len(stolen.Attempts), len(funds.Attempts), len(tech.Attempts), len(providers))
	return okHard && okFunds && okTech, detail
}

func refundBound(ctx context.Context, e *Env) (bool, string) {
	p, err := e.captured(ctx, "refund", 10000)
	if err != nil {
		return false, err.Error()
	}
	const n, each = 20, 1000
	var mu sync.Mutex
	accepted, rejected, errs := 0, 0, 0
	fanOut(n, n, func(i int) {
		r, err := e.C.Do(ctx, "POST", "/v1/payments/"+p.ID+"/refunds",
			map[string]string{"Idempotency-Key": e.key("refund", fmt.Sprint(i))}, map[string]int64{"amount": each})
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err != nil:
			errs++
		case r.Status >= 200 && r.Status < 300:
			accepted++
		default:
			rejected++
		}
	})
	final, err := e.Get(ctx, p.ID)
	if err != nil {
		return false, err.Error()
	}
	detail := fmt.Sprintf("captured %d; %d refunds of %d: %d accepted, %d rejected, %d errors; refunded_amount = %d",
		final.Captured, n, each, accepted, rejected, errs, final.Refunded)
	pass := final.Refunded <= final.Captured && final.Refunded == int64(accepted*each) && errs == 0
	return pass, detail
}

func chargebackBody(id, ref string) []byte {
	b, _ := json.Marshal(map[string]string{"id": id, "type": "chargeback.opened", "reference": ref, "reason_code": "4837"})
	return b
}

func webhookAuthenticity(ctx context.Context, e *Env) (bool, string) {
	p, err := e.captured(ctx, "wh-auth", 11000)
	if err != nil {
		return false, err.Error()
	}
	secret, ok := e.Secrets[p.Provider]
	if !ok {
		return false, "no webhook secret configured for provider " + p.Provider
	}
	body := chargebackBody("evt-"+e.Run+"-forged", p.ProviderRef)
	path := "/v1/webhooks/" + p.Provider
	send := func(hdr string, b []byte, provider string) int {
		h := map[string]string{}
		if hdr != "" {
			h["X-Signature"] = hdr
		}
		r, _ := e.C.Do(ctx, "POST", "/v1/webhooks/"+provider, h, b)
		return r.Status
	}
	_ = path
	now := time.Now()
	noSig := send("", body, p.Provider)
	wrongKey := send(SignWebhook("not-the-secret", now, body), body, p.Provider)
	tampered := send(SignWebhook(secret, now, body), chargebackBody("evt-"+e.Run+"-forged", "SOMEONE-ELSE"), p.Provider)
	stale := send(SignWebhook(secret, now.Add(-10*time.Minute), body), body, p.Provider)
	unknown := send(SignWebhook(secret, now, body), body, "no-such-provider")
	after, err := e.Get(ctx, p.ID)
	if err != nil {
		return false, err.Error()
	}
	detail := fmt.Sprintf("no signature %d, wrong secret %d, tampered body %d, stale timestamp %d (want 401); unknown provider %d (want 404); payment still %q",
		noSig, wrongKey, tampered, stale, unknown, after.Status)
	pass := noSig == 401 && wrongKey == 401 && tampered == 401 && stale == 401 && unknown == 404 && after.Status == "captured"
	return pass, detail
}

func webhookResend(ctx context.Context, e *Env) (bool, string) {
	p, err := e.captured(ctx, "wh-resend", 11100)
	if err != nil {
		return false, err.Error()
	}
	secret := e.Secrets[p.Provider]
	body := chargebackBody("evt-"+e.Run+"-resend", p.ProviderRef)
	codes := map[int]int{}
	for i := 0; i < 5; i++ {
		r, _ := e.Webhook(ctx, p.Provider, time.Now(), secret, body)
		codes[r.Status]++
	}
	after, err := e.Get(ctx, p.ID)
	if err != nil {
		return false, err.Error()
	}
	detail := fmt.Sprintf("5 deliveries of one event -> responses %v; payment status %q (want disputed)", codes, after.Status)
	return codes[200] == 5 && after.Status == "disputed", detail
}

func webhookParallel(ctx context.Context, e *Env) (bool, string) {
	// A race is probabilistic: repeat with fresh payments so one lucky run cannot hide it.
	const rounds, n = 8, 40
	total := map[int]int{}
	notDisputed := 0
	for r := 0; r < rounds; r++ {
		p, err := e.captured(ctx, fmt.Sprintf("wh-parallel-%d", r), 11200+int64(r)*100)
		if err != nil {
			return false, err.Error()
		}
		secret := e.Secrets[p.Provider]
		body := chargebackBody(fmt.Sprintf("evt-%s-parallel-%d", e.Run, r), p.ProviderRef)
		var mu sync.Mutex
		fanOut(n, n, func(int) {
			resp, _ := e.Webhook(ctx, p.Provider, time.Now(), secret, body)
			mu.Lock()
			total[resp.Status]++
			mu.Unlock()
		})
		after, err := e.Get(ctx, p.ID)
		if err != nil || after.Status != "disputed" {
			notDisputed++
		}
	}
	detail := fmt.Sprintf("%d rounds x %d parallel deliveries of one event -> responses %v; payments not disputed: %d", rounds, n, total, notDisputed)
	return total[200] == rounds*n && notDisputed == 0, detail
}

func panNeverLeaks(ctx context.Context, e *Env, logFile string) (bool, string) {
	tokResp, err := e.C.Do(ctx, "POST", "/v1/tokens", nil, map[string]any{"number": panLeak, "exp_month": 12, "exp_year": 2031})
	if err != nil || tokResp.Status != http.StatusCreated {
		return false, fmt.Sprintf("tokenize failed: %v", err)
	}
	var tk struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(tokResp.Body, &tk)
	_, p, err := e.Pay(ctx, e.key("pan"), PayReq{"m-chk", 12300, "BRL", tk.Token, true})
	if err != nil || p == nil {
		return false, fmt.Sprintf("payment failed: %v", err)
	}
	surfaces := map[string][]byte{"token response": tokResp.Body}
	for name, path := range map[string]string{"payment": "/v1/payments/" + p.ID, "metrics": "/metrics", "provider health": "/v1/providers/health"} {
		r, err := e.C.Do(ctx, "GET", path, nil, nil)
		if err == nil {
			surfaces[name] = r.Body
		}
	}
	pr, _ := e.C.Do(ctx, "POST", "/v1/payments", map[string]string{"Idempotency-Key": e.key("pan")}, PayReq{"m-chk", 12300, "BRL", tk.Token, true})
	surfaces["payment replay"] = pr.Body
	var leaks []string
	for name, b := range surfaces {
		if strings.Contains(string(b), panLeak) {
			leaks = append(leaks, name)
		}
	}
	scanned := len(surfaces)
	if logFile != "" {
		raw, err := os.ReadFile(logFile)
		if err != nil {
			return false, "cannot read log file: " + err.Error()
		}
		scanned++
		if strings.Contains(string(raw), panLeak) {
			leaks = append(leaks, "server log")
		}
	}
	exposed := p.BIN == panLeak[:6] && p.Last4 == panLeak[len(panLeak)-4:]
	detail := fmt.Sprintf("scanned %d surfaces for the full PAN, leaks: %v; payment exposes bin %q and last4 %q", scanned, leaks, p.BIN, p.Last4)
	return len(leaks) == 0 && exposed, detail
}

func abortsDontPoison(ctx context.Context, e *Env) (bool, string) {
	// let any breaker opened by earlier invariants close first, so this one is judged on its own
	if !waitHealthy(ctx, e, 40*time.Second) {
		return false, "providers still unhealthy before the test; cannot attribute cause"
	}
	tok, err := e.Token(ctx, panVisa)
	if err != nil {
		return false, err.Error()
	}
	const n = 12
	fanOut(n, n, func(i int) {
		short, cancel := context.WithTimeout(ctx, 15*time.Millisecond)
		defer cancel()
		_, _, _ = e.Pay(short, e.key("poison", fmt.Sprint(i)), PayReq{"m-chk", 15000 + int64(i)*100, "BRL", tok, true})
	})
	time.Sleep(300 * time.Millisecond)
	open := openProviders(ctx, e)
	r, p, _ := e.Pay(ctx, e.key("poison", "next-customer"), PayReq{"m-chk", 16000, "BRL", tok, true})
	paid := p != nil && p.Status == "captured"
	detail := fmt.Sprintf("%d clients disconnected mid-request -> breakers open: %v; next customer's payment: HTTP %d", n, open, r.Status)
	if paid {
		detail += " captured"
	}
	return len(open) == 0 && paid, detail
}

func openProviders(ctx context.Context, e *Env) []string {
	r, err := e.C.Do(ctx, "GET", "/v1/providers/health", nil, nil)
	if err != nil {
		return nil
	}
	var h map[string]string
	_ = json.Unmarshal(r.Body, &h)
	var open []string
	for name, st := range h {
		if st == "open" { // "half-open" is a probe window, not an outage
			open = append(open, name)
		}
	}
	sort.Strings(open)
	return open
}

func waitHealthy(ctx context.Context, e *Env, max time.Duration) bool {
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if len(openProviders(ctx, e)) == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
	return len(openProviders(ctx, e)) == 0
}
