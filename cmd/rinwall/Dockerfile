# The proxy is pure Go - no cgo, on purpose (see the pure-Go SQLite/Postgres
# driver choices in go.mod) - so a static binary and a tiny final image are
# both free. Built from the repo root: `docker build -f cmd/rinwall/Dockerfile .`
# (the docker-compose.yml at the repo root does this for you).

FROM golang:1.27-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/rinwall

# Alpine, not distroless/scratch, specifically so this stage can define a
# HEALTHCHECK with nothing more exotic than BusyBox wget - what
# docker-compose.yml's `depends_on: proxy: condition: service_healthy` (for
# mockupstream, which refuses to start until the proxy is already serving
# GET /biscuit-keys) relies on. A hardened, shell-less distroless build is a
# reasonable follow-up once this is more than a getting-started reference
# image, not a requirement for it to be a real, working one now.
FROM alpine:3.20
# GHCR links the package to the repository named here.
LABEL org.opencontainers.image.source="https://github.com/RinwallDev/rinwall"
RUN apk add --no-cache ca-certificates
COPY --from=build /out/proxy /usr/local/bin/proxy
WORKDIR /app
# config/policies/examples are bind-mounted by docker-compose.yml (see
# config/config.docker.yaml's relative paths), not baked in here - so
# editing tools.yaml or the Rego bundle doesn't require rebuilding the
# image. /data holds the audit log and SQLite state, backed by a named
# volume so it survives a container restart.
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/proxy"]
CMD ["config/config.docker.yaml"]
