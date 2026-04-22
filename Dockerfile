# ── Build stage ────────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

# Install build dependencies (cgo is disabled so only native Go is needed).
RUN apk add --no-cache git

WORKDIR /app

# Cache module downloads separately from source code.
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build a statically linked binary.
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /scanvault .

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /scanvault /scanvault

# Run as non-root user (distroless default uid 65532).
USER nonroot:nonroot

EXPOSE 8080

ENTRYPOINT ["/scanvault"]
