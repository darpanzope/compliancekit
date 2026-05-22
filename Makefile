.PHONY: build run test test-external lint fmt tidy clean setup check docs docs-check api api-check ui ui-setup ui-check help
.DEFAULT_GOAL := help

# Tools installed via `go install` land in $GOPATH/bin which is often
# not on a developer's shell PATH. Resolve once and reuse so every
# recipe finds them.
GOBIN   := $(shell go env GOPATH)/bin
export PATH := $(GOBIN):$(PATH)

# v1.4 Phase 0: UI build pipeline pins. Bump TAILWIND_VERSION + the
# vendored htmx/Alpine/Preline filenames together; `make ui-check`
# guarantees compiled output in internal/server/assets/ matches.
TAILWIND_VERSION := 3.4.17
TAILWIND_BIN     := .cache/tailwindcss-$(TAILWIND_VERSION)
HTMX_VERSION     := 1.9.10
ALPINE_VERSION   := 3.13.7
PRELINE_VERSION  := 2.0.3

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
	go test -race -short -timeout=120s ./...

test-external: ## v1.0 contract test under the perspective of an external embedder
	go test -tags=external -timeout=120s ./pkg/compliancekit/...

bench-server: ## v1.11 phase 9 — perf benchmarks (100k findings / 10k resources / 1k scans)
	go test -bench=. -benchmem -benchtime=3s -run=^$ -timeout=15m ./internal/server/api/

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

docs: ## regenerate docs/checks.md from the live registry
	go run ./cmd/gencheckdocs

docs-check: ## fail if docs/checks.md is stale (CI gate)
	go run ./cmd/gencheckdocs -check

api: ## regenerate pkg/compliancekit/api.txt from the public surface
	go run ./cmd/genapi

api-check: ## fail if pkg/compliancekit/api.txt is stale (v1.0 SemVer gate)
	go run ./cmd/genapi -check

ui-setup: ## download the pinned Tailwind standalone CLI (one-time, contributors only)
	@TAILWIND_VERSION=$(TAILWIND_VERSION) ./scripts/ui-setup.sh

ui: ## compile internal/server/assets/ from src/input.css + vendor/ (requires ui-setup)
	@test -x $(TAILWIND_BIN) || (echo "tailwindcss not installed — run 'make ui-setup' first"; exit 1)
	@mkdir -p internal/server/assets
	@$(TAILWIND_BIN) \
		-c internal/server/ui/tailwind.config.js \
		-i internal/server/ui/src/input.css \
		-o internal/server/assets/app.css \
		--minify
	@cp internal/server/ui/vendor/htmx-$(HTMX_VERSION).min.js     internal/server/assets/htmx.min.js
	@cp internal/server/ui/vendor/alpine-$(ALPINE_VERSION).min.js internal/server/assets/alpine.min.js
	@cp internal/server/ui/vendor/preline-$(PRELINE_VERSION).js   internal/server/assets/preline.js
	@cp internal/server/ui/src/app.js                              internal/server/assets/app.js
	@cp internal/server/ui/src/a11y.js                             internal/server/assets/a11y.js
	@echo "ui assets compiled → internal/server/assets/"

ui-check: ## fail if internal/server/assets/ is stale (CI gate)
	@$(MAKE) ui
	@git diff --exit-code -- internal/server/assets/ || (echo ""; echo "internal/server/assets/ is stale — run 'make ui' and commit the regenerated files"; exit 1)

check: lint test test-external build docs-check api-check ui-check ## pre-push gate: lint + tests + build + docs + api + ui freshness

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
