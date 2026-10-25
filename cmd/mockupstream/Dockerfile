# mockupstream stands in for "the real enterprise API" in the reference
# stack - it's what makes `docker compose up` demonstrate the whole loop
# (a real biscuit-verified mutation, a real MCP passthrough call) without
# needing a real upstream service. Built from the repo root:
# `docker build -f cmd/mockupstream/Dockerfile .`

FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/mockupstream ./cmd/mockupstream

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/mockupstream /usr/local/bin/mockupstream
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --start-period=5s --retries=10 \
    CMD wget -qO- http://127.0.0.1:8000/users/42 || exit 1
ENTRYPOINT ["/usr/local/bin/mockupstream"]
