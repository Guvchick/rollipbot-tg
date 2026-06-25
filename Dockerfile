# syntax=docker/dockerfile:1

# --- build stage: fully static, CGO-free binary (modernc.org/sqlite is pure Go) ---
FROM golang:1.26-alpine AS build
WORKDIR /src

# cache deps first
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

# build
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/bot ./cmd/bot

# --- runtime stage: tiny Alpine with CA certs + tzdata, non-root ---
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 app \
    && mkdir -p /data
WORKDIR /app
COPY --from=build /out/bot /app/bot
COPY config.yaml /app/config.yaml
RUN chown -R app:app /data /app
USER app

# DB lives on a mounted volume by default (see docker-compose.yml).
ENV STORAGE_DSN=/data/ip-roller.db
VOLUME ["/data"]

ENTRYPOINT ["/app/bot"]
CMD ["-config", "/app/config.yaml"]
