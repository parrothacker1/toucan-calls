FROM golang:1.25.0-alpine AS builder
RUN apk add --no-cache git ca-certificates gcc musl-dev pkgconf opus-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
RUN apk add --no-cache opusfile-dev
COPY . .
RUN CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o toucan-server ./cmd/server/server.go

FROM alpine:3.21 AS runner
RUN apk add --no-cache ca-certificates opus opusfile sqlite-libs
WORKDIR /root
COPY --from=builder /app/toucan-server .
CMD ["/root/toucan-server"]
