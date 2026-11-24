.PHONY: build test race demo
build:
	go build -o bin/invariants ./cmd/invariants
test:
	go test -count=1 ./...
race:
	go test -race -count=1 ./...
# Run the invariants against a payment-orchestrator-go running on :8080.
demo: build
	./bin/invariants -target http://localhost:8080 -concurrency 20
