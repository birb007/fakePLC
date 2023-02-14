FROM golang:1.19-alpine AS builder
WORKDIR /go/src/fakePLC/
COPY . .
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -installsuffix=cgo -ldflags="-s -w" -a -o /go/bin/fakePLC

FROM gcr.io/distroless/static-debian11:nonroot
COPY --from=builder /go/bin/fakePLC /fakePLC
ENTRYPOINT ["/fakePLC"]
