FROM golang:1.25.0-alpine AS builder
RUN apk add --no-cache git ca-certificates
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/server/server.go -ldflags="-w -s" -o toucan-server .

FROM gcr.io/distroless/cc AS runner
WORKDIR /root
COPY --from=builder /app/toucan-server .
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
CMD ["/root/toucan-server"]
