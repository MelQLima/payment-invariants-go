// Command invariants attacks a payment API with concurrency, retries and
// forged events, and verifies the invariants that must always hold.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/MelQLima/payment-invariants-go/internal/checker"
)

type kv map[string]string

func (m kv) String() string { return fmt.Sprint(map[string]string(m)) }
func (m kv) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" || v == "" {
		return fmt.Errorf("want provider=secret, got %q", s)
	}
	m[k] = v
	return nil
}

func main() {
	secrets := kv{"acquirer-a": "whsec_acquirer_a", "psp-b": "whsec_psp_b", "gateway-c": "whsec_gateway_c"}
	target := flag.String("target", "http://localhost:8080", "base URL of the payment API")
	conc := flag.Int("concurrency", 20, "parallel requests in the load invariant")
	jsonOut := flag.Bool("json", false, "print the report as JSON")
	logFile := flag.String("log-file", "", "server log to scan for the card number (optional)")
	only := flag.String("only", "", "run a single invariant, e.g. I9")
	flag.Var(secrets, "webhook-secret", "provider=secret for signing webhooks (repeatable)")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	rep, err := checker.Run(ctx, checker.Options{Target: *target, Concurrency: *conc, Secrets: secrets, LogFile: *logFile, Only: *only})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if *jsonOut {
		_ = rep.WriteJSON(os.Stdout)
	} else {
		fi, _ := os.Stdout.Stat()
		rep.WriteText(os.Stdout, fi.Mode()&os.ModeCharDevice != 0 || os.Getenv("FORCE_COLOR") != "")
	}
	if rep.Failed() > 0 {
		os.Exit(1)
	}
}
