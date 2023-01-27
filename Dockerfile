FROM golang:1.19-alpine AS builder
WORKDIR /go-src
COPY . .
RUN go mod tidy -v
RUN CGO_ENABLED=0 go build -v -tags 'netgo' -o out/f660_exporter .

FROM alpine:3.17
RUN apk --no-cache add ca-certificates tzdata && update-ca-certificates
WORKDIR /opt/f660_exporter
COPY --from=builder /go-src/out/f660_exporter /opt/f660_exporter/f660_exporter
CMD ["./f660_exporter"]
