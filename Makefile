.PHONY: build run test lint fmt tidy clean setup check help
.DEFAULT_GOAL := help

# Tools installed via `go install` land in $GOPATH/bin which is often
# not on a developer's shell PATH. Resolve once and reuse so every
# recipe finds them.
GOBIN   := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

BIN     := bin/compliancekit
PKG     := github.com/darpanzope/compliancekit
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
           -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.date=$(DATE)

build: ## build the binary into bin/compliancekit
	@mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) ./cmd/compliancekit
	@echo "built $(BIN)"

run: ## run via go run; pass args via ARGS=
	go run ./cmd/compliancekit $(ARGS)

test: ## unit tests with race detector
	go test -race -timeout=60s ./...

test-integration: ## bring up docker harness, run integration tests, tear down
	docker compose -f test/compose.yaml up -d
	@trap "docker compose -f test/compose.yaml down" EXIT; \
		go test -race -timeout=120s -tags=integration ./...

lint: ## golangci-lint
	golangci-lint run

fmt: ## format all Go files
	gofmt -s -w .
	@command -v goimports >/dev/null && goimports -w -local $(PKG) . || true

tidy: ## tidy go.mod / go.sum
	go mod tidy

clean: ## remove build artifacts
	rm -rf bin/

setup: ## install development tools (golangci-lint, goimports, lefthook) and install git hooks
	@test -x $(GOBIN)/golangci-lint || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@test -x $(GOBIN)/goimports     || go install golang.org/x/tools/cmd/goimports@latest
	@test -x $(GOBIN)/lefthook      || go install github.com/evilmartians/lefthook@latest
	$(GOBIN)/lefthook install
	@echo "setup complete (hooks installed)"
	@echo
	@echo "Tip: add this to your shell rc so the tools are on PATH everywhere:"
	@echo "  export PATH=\"\$$(go env GOPATH)/bin:\$$PATH\""

check: lint test build ## pre-push gate: lint + test + build

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
