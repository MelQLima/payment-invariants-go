// Package checker attacks a payment API from the outside (black box) and
// verifies the invariants a payment system must keep under concurrency,
// retries and failures: no double charge, no money out of thin air, no
// forged or replayed webhook, no PAN in any response.
package checker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// Resp is one HTTP exchange.
type Resp struct {
	Status int
	Body   []byte
	Dur    time.Duration
}

// Client is a tiny JSON-over-HTTP client for the API under test.
type Client struct {
	Base string
	HTTP *http.Client
}

// NewClient returns a client with a connection pool sized for the load.
func NewClient(base string, concurrency int) *Client {
	tr := &http.Transport{MaxIdleConns: concurrency * 2, MaxIdleConnsPerHost: concurrency * 2, IdleConnTimeout: 30 * time.Second}
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second}}
}

// Do sends body (any JSON-encodable value, or raw []byte) and returns the response.
func (c *Client) Do(ctx context.Context, method, path string, hdr map[string]string, body any) (Resp, error) {
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return Resp{}, err
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return Resp{}, err
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	start := time.Now()
	res, err := c.HTTP.Do(req)
	if err != nil {
		return Resp{Dur: time.Since(start)}, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return Resp{Status: res.StatusCode, Body: raw, Dur: time.Since(start)}, err
}

// Attempt mirrors one provider call recorded by the API.
type Attempt struct {
	Provider string `json:"provider"`
	Class    string `json:"class"`
	Approved bool   `json:"approved"`
}

// Payment is the subset of the payment resource the invariants need.
type Payment struct {
	ID          string    `json:"id"`
	Status      string    `json:"status"`
	Captured    int64     `json:"captured_amount"`
	Refunded    int64     `json:"refunded_amount"`
	Provider    string    `json:"provider"`
	ProviderRef string    `json:"provider_reference"`
	BIN         string    `json:"bin"`
	Last4       string    `json:"last4"`
	Attempts    []Attempt `json:"attempts"`
}

// PayReq is the create-payment request.
type PayReq struct {
	MerchantID string `json:"merchant_id"`
	Amount     int64  `json:"amount"`
	Currency   string `json:"currency"`
	CardToken  string `json:"card_token"`
	Capture    bool   `json:"capture"`
}

// Env carries what scenarios need.
type Env struct {
	C           *Client
	Secrets     map[string]string // webhook secret per provider
	Concurrency int
	Run         string // unique per run, keeps idempotency keys fresh
}

// Token tokenizes a test PAN and returns the token.
func (e *Env) Token(ctx context.Context, pan string) (string, error) {
	r, err := e.C.Do(ctx, "POST", "/v1/tokens", nil, map[string]any{"number": pan, "exp_month": 12, "exp_year": 2031})
	if err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	if r.Status != http.StatusCreated || json.Unmarshal(r.Body, &out) != nil || out.Token == "" {
		return "", fmt.Errorf("tokenize: HTTP %d %s", r.Status, truncate(string(r.Body), 120))
	}
	return out.Token, nil
}

// Pay creates a payment under an idempotency key.
func (e *Env) Pay(ctx context.Context, key string, req PayReq) (Resp, *Payment, error) {
	r, err := e.C.Do(ctx, "POST", "/v1/payments", map[string]string{"Idempotency-Key": key}, req)
	if err != nil {
		return r, nil, err
	}
	return r, parsePayment(r), nil
}

// Get fetches a payment.
func (e *Env) Get(ctx context.Context, id string) (*Payment, error) {
	r, err := e.C.Do(ctx, "GET", "/v1/payments/"+id, nil, nil)
	if err != nil {
		return nil, err
	}
	p := parsePayment(r)
	if p == nil {
		return nil, fmt.Errorf("get %s: HTTP %d", id, r.Status)
	}
	return p, nil
}

func parsePayment(r Resp) *Payment {
	if r.Status < 200 || r.Status > 299 {
		return nil
	}
	var p Payment
	if json.Unmarshal(r.Body, &p) != nil || p.ID == "" {
		return nil
	}
	return &p
}

// SignWebhook builds the "t=<unix>,v1=<hmac>" header over "timestamp.body".
func SignWebhook(secret string, ts time.Time, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(m, "%d.", ts.Unix())
	m.Write(body)
	return fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(m.Sum(nil)))
}

// Webhook posts a signed provider notification.
func (e *Env) Webhook(ctx context.Context, provider string, ts time.Time, secret string, body []byte) (Resp, error) {
	return e.C.Do(ctx, "POST", "/v1/webhooks/"+provider, map[string]string{"X-Signature": SignWebhook(secret, ts, body)}, body)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func percentile(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	i := int(float64(len(s)-1) * p)
	return s[i]
}
