FROM golang:1.26-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o token-server .

# ─── Runtime ──────────────────────────────────────────────────
FROM alpine:3.23

LABEL org.opencontainers.image.title="gha-token-server"
LABEL org.opencontainers.image.description="GitHub App backed token server for self-hosted Actions runners"
LABEL org.opencontainers.image.source="https://github.com/nkg/gha-token-server"
LABEL org.opencontainers.image.licenses="MIT"

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -h /app appuser

WORKDIR /app
COPY --from=builder /build/token-server .

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD ["wget", "--spider", "-q", "http://localhost:8080/health"]

ENTRYPOINT ["./token-server"]
