# payment-invariants-go

A **black-box invariant and chaos checker for payment APIs**, written in Go with zero dependencies.

Unit tests prove that a function works. This tool proves that a *payment system* keeps its promises when
the real world misbehaves: clients retry, time out and disconnect, providers resend webhooks in parallel,
refunds race each other. It attacks the API over HTTP and checks eleven invariants that must **always** hold.

It was built against [payment-orchestrator-go](https://github.com/MelQLima/payment-orchestrator-go) and, on its
first run, **found two real bugs in it** (see below).

## The invariants

| # | Invariant | How it is attacked |
|---|---|---|
| I1 | One idempotency key creates exactly one payment, and the acquirer is called once | 50 identical concurrent requests |
| I2 | Same key + same body replays; same key + different body is rejected (422) | replay and mutate |
| I3 | N distinct requests create N distinct, captured payments | 200 requests under load, p50/p95 |
| I4 | Hard declines and insufficient funds never cascade to another acquirer; technical failures do | stolen card, no funds, issuer down |
| I5 | Concurrent refunds never move more money than was captured; every 2xx moved money | 20 parallel refunds of 10% each |
| I6 | Forged, tampered, stale and unknown-provider webhooks change nothing | wrong secret, altered body, old timestamp |
| I7 | A provider that resends an event gets 200 each time; the event applies once | 5 sequential deliveries |
| I8 | The same event delivered in parallel applies once and never returns 5xx | 8 rounds x 40 parallel deliveries |
| I9 | The card number appears in no response, metric or log line; only BIN and last4 | scans 6 surfaces + the server log |
| I10 | A client that times out and retries never causes a second approval | abort mid-flight, retry with the same key |
| I11 | Clients that disconnect must not open the circuit breakers | abort 12 requests, then pay the next customer |

## Run it

```bash
# 1. start the system under test (any payment API with the same contract works)
git clone https://github.com/MelQLima/payment-orchestrator-go && cd payment-orchestrator-go
go run ./cmd/api > /tmp/orch.log &

# 2. attack it
go run github.com/MelQLima/payment-invariants-go/cmd/invariants@latest -log-file /tmp/orch.log
```

Flags: `-target`, `-concurrency`, `-json` (machine-readable report), `-only I8`, `-log-file`, `-webhook-secret provider=secret`.
Exit code is `0` when every invariant holds, `1` when any is violated, `2` when the target is unreachable — so it drops into CI as a release gate.

## What it found

Run against the orchestrator as it was, **2 of 11 invariants were violated**:

- **I8 (parallel duplicate webhooks):** the dedup check and the "mark as seen" step were separate critical sections.
  Two parallel deliveries of the same chargeback both reached the state machine; the second hit an illegal transition and answered **500**.
  Fix: reserve the event ID atomically before applying it, release it if processing fails.
- **I11 (client aborts poison the breakers):** when a client disconnected mid-authorization, the cancelled context was recorded as a
  *provider technical failure*. A dozen impatient clients opened the breakers of two acquirers, and **every following customer got 503 for 30 seconds**.
  The same bug also cascaded the cancelled payment to the next acquirer, and a retry with the same key replayed `declined` (12 of 12) instead of being paid.
  Fix: when the caller's context is done, return — do not feed the breaker and do not cascade.

[`docs/orchestrator-fixes.patch`](docs/orchestrator-fixes.patch) contains both fixes. With them applied: **11/11 invariants hold**, and the retries after an abort end `captured` (12 of 12).

## Design notes

- **Black box on purpose.** It only speaks HTTP, so it can guard any implementation (Go, Node, a sandbox of a real acquirer) and cannot be fooled by internal shortcuts.
- **Races are probabilistic**, so I8 repeats with fresh payments. The first version passed by luck; the hardened one catches the bug on every run.
- **The checker is tested too.** `checker_test.go` runs I1 against a correct fake and against one that ignores `Idempotency-Key` — the checker must pass the first and fail the second.
- **Judge each invariant on its own cause.** I11 waits for earlier breakers to leave `open` before it starts, so a failure is attributable.

## Limits

- Provider outages and latency cannot be injected from outside; the target's simulators provide the declines (`..43`, `..51`, `..91` amounts). A real sandbox would need a fault-injecting proxy in front of it.
- Concurrency findings are statistical: a green run is evidence, not proof.
