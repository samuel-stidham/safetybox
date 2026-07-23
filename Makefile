BIN            := safetybox
PKG            := github.com/samuel-stidham/$(BIN)/v3
LOCAL_VERSION  := $(shell git describe --tags --always --dirty)
GO_VERSION     := 1.26
GOBIN          := $(shell go env GOPATH)/bin
GOVULNCHECK_VERSION := v1.6.0
# The identity uses a real scrypt KDF, which is deliberately slow, and the
# race detector multiplies that cost. The default 10m go test timeout is
# too tight for the full suite on a slower CI runner, so the -race targets
# get more headroom. This is wall-clock time, not a hang.
RACE_TIMEOUT   := 20m

.DEFAULT_GOAL := help

.PHONY: help
help: ## Display all available targets.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-14s\033[0m %s\n", $$1, $$2}'

.PHONY: test-vars
test-vars: ## Print resolved variables.
	@echo $(BIN)
	@echo $(PKG)
	@echo $(LOCAL_VERSION)
	@echo $(GO_VERSION)

.PHONY: build
build: ## Build the safetybox binary into bin/.
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(LOCAL_VERSION)" -o bin/$(BIN) .

.PHONY: dev
dev: ## Build a dev binary into bin/ for local testing (version tagged -dev).
	CGO_ENABLED=0 go build -ldflags "-X main.version=$(LOCAL_VERSION)-dev" -o bin/$(BIN) .

.PHONY: install
install: ## Officially install safetybox to $(GOPATH)/bin.
	CGO_ENABLED=0 GOBIN=$(GOBIN) go install -ldflags "-X main.version=$(LOCAL_VERSION)" .

artifacts: ## Create the artifacts folder.
	mkdir -p ./artifacts

.PHONY: clean
clean: ## Clean up build output and artifacts.
	rm -rf bin/
	rm -rf artifacts/

.PHONY: cover
cover: artifacts ## Run tests and write the coverage profile.
	CGO_ENABLED=1 go test -race -timeout $(RACE_TIMEOUT) -coverprofile=artifacts/coverage.out -covermode=atomic ./...

.PHONY: cover-func
cover-func: cover ## Per-function coverage summary in the terminal.
	go tool cover -func=artifacts/coverage.out

.PHONY: cover-html
cover-html: cover ## Render the coverage report (stdlib HTML).
	go tool cover -html=artifacts/coverage.out -o artifacts/coverage.html
	@echo "wrote artifacts/coverage.html"

.PHONY: dep-tidy
dep-tidy: ## Remove unused dependencies and add missing dependencies.
	go mod tidy -go=$(GO_VERSION)

.PHONY: update-dep
update-dep: ## Update specific dependencies. Usage: make update-dep DEP=filippo.io/age
	go get -u $(DEP)

.PHONY: gci
gci: ## Rewrite import grouping (stdlib / safetybox / third-party).
	gci write --custom-order \
		-s standard \
		-s "prefix($(PKG))" \
		-s default \
		main.go cmd internal

.PHONY: gofumpt
gofumpt: ## Run the gofumpt formatter.
	gofumpt -l -w .

.PHONY: lint-go
lint-go: ## Run golangci-lint.
	golangci-lint run --fix

.PHONY: lint
lint: gofumpt gci lint-go ## Run the linters.

.PHONY: test
test: ## Run all Go tests. Fast, for the local loop.
	go test -count=1 ./...

.PHONY: test-race
test-race: ## Run all Go tests with the race detector. Slower, needs cgo. CI runs this.
	CGO_ENABLED=1 go test -race -count=1 -timeout $(RACE_TIMEOUT) ./...

.PHONY: vuln
vuln: ## Scan for known vulnerabilities in dependencies.
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
