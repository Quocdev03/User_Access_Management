FROM golang:1.27.0-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ENV CGO_ENABLED=0

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /app/bin/server ./cmd/server \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /app/bin/worker ./cmd/worker \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /app/bin/migrate ./cmd/migrate \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /app/bin/avatar-migrate ./cmd/avatar-migrate \
    && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /app/bin/bootstrap-admin ./cmd/bootstrap-admin

FROM alpine:3.23

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

COPY --from=builder /app/bin/server ./server
COPY --from=builder /app/bin/worker ./worker
COPY --from=builder /app/bin/migrate ./migrate
COPY --from=builder /app/bin/avatar-migrate ./avatar-migrate
COPY --from=builder /app/bin/bootstrap-admin ./bootstrap-admin
COPY --from=builder /app/migrations ./migrations

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./server"]
