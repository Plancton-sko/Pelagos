FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o palagos-server ./cmd/palagos-server
RUN CGO_ENABLED=0 GOOS=linux go build -o palagos ./cmd/palagos

FROM alpine:3.19

RUN apk add --no-cache tor bash netcat-openbsd

WORKDIR /app
COPY --from=builder /app/palagos-server /app/palagos-server
COPY --from=builder /app/palagos /app/palagos
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

EXPOSE 8080 9050 9051

ENTRYPOINT ["/app/entrypoint.sh"]
