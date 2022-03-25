FROM golang:alpine as builder

WORKDIR /vrrp-go

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -buildvcs=false -ldflags="-s -w" -o vr ./example

FROM alpine

RUN apk add --no-cache iptables

COPY --from=builder /vrrp-go/vr /usr/local/bin/vr

ENTRYPOINT ["/usr/local/bin/vr"]
