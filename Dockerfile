FROM golang:1.25.13-alpine AS builder

WORKDIR /src

COPY go.mod ./

COPY . .

RUN CGO_ENABLED=0 GOOS=linux \
    go build \
    -o /app/server \
    main.go


FROM alpine:3.20

WORKDIR /app

RUN addgroup -S appgroup \
    && adduser -S appuser -G appgroup

COPY --from=builder /app/server /app/server

COPY templates /app/templates

COPY static /app/static

USER appuser

EXPOSE 8080

ENV PORT=8080

CMD ["/app/server"]