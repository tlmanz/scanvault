# ──────────────────────────────────────────────────────────────────────────────
# ScanVault Makefile
# ──────────────────────────────────────────────────────────────────────────────

# Load .env if it exists (never fail if missing)
-include .env
export

# Build output
BINARY     := scanvault
BUILD_DIR  := bin
CMD_PATH   := .

# Docker Compose
COMPOSE    := docker compose
IMAGE_NAME := scanvault
TEST_PKGS  := $(shell go list -f '{{if or (len .TestGoFiles) (len .XTestGoFiles)}}{{.ImportPath}}{{end}}' ./... | sed '/^$$/d')

.PHONY: help run build clean test lint vet fmt \
        docker-build docker-up docker-down docker-logs docker-restart \
        migrate migrate-status migrate-down migrate-dry

# ── Default ───────────────────────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Development ───────────────────────────────────────────────────────────────

run: ## Load .env and run the server with go run
	go run $(CMD_PATH)

build: ## Compile the binary to ./bin/scanvault
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="-w -s" -o $(BUILD_DIR)/$(BINARY) $(CMD_PATH)

run-binary: build ## Build then run the compiled binary
	./$(BUILD_DIR)/$(BINARY)

clean: ## Remove the build directory
	rm -rf $(BUILD_DIR)

# ── Code Quality ──────────────────────────────────────────────────────────────

vet: ## Run go vet
	go vet ./...

fmt: ## Format code with gofmt
	gofmt -w -s .

lint: ## Run golangci-lint (must be installed)
	golangci-lint run ./...

test: ## Run tests with race + coverage (test packages only)
	go test -race -coverprofile=coverage.out $(TEST_PKGS)

test-verbose: ## Run all tests with verbose output
	go test -race -v ./...



# ── Database / Goose ─────────────────────────────────────────────────────────

GOOSE := goose -dir migrations postgres "$(DATABASE_URL)"

migrate: ## Apply all pending goose migrations
	$(GOOSE) up

migrate-status: ## Show goose migration status
	$(GOOSE) status

migrate-down: ## Roll back the last goose migration
	$(GOOSE) down

migrate-dry: ## Print the next pending migration SQL (no-run)
	$(GOOSE) up --dry-run

# ── Docker Compose ────────────────────────────────────────────────────────────

docker-build: ## Build the Docker image
	$(COMPOSE) build

docker-up: ## Start all services (detached)
	$(COMPOSE) up --build -d

docker-down: ## Stop and remove all containers (keeps volumes)
	$(COMPOSE) down

docker-down-clean: ## Stop containers and remove volumes
	$(COMPOSE) down -v

docker-logs: ## Tail logs from the api service
	$(COMPOSE) logs -f api

docker-restart: ## Restart the api service only
	$(COMPOSE) restart api

docker-ps: ## Show running compose services
	$(COMPOSE) ps

# ── Env ───────────────────────────────────────────────────────────────────────

env-copy: ## Copy .env.example to .env (safe - won't overwrite existing)
	@[ -f .env ] && echo ".env already exists, skipping." || (cp .env.example .env && echo "Created .env from .env.example")
