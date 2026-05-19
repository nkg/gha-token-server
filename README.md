# gha-token-server

GitHub App backed token-minting service for self-hosted GitHub
Actions runners. Multi-tenant (one or more orgs per server), cached
installation tokens with thundering-herd protection, Prometheus
metrics, JSON structured logs.

Designed to sit alongside
[nkg/gha-nomad-dispatcher](https://github.com/nkg/gha-nomad-dispatcher)
— the dispatcher calls this service to mint registration tokens for
each ephemeral runner it spawns. Can also be consumed directly by
any client that needs short-lived runner tokens (Ansible, CI
plumbing, custom autoscalers).

Lifted from a working internal deployment that's been running in
production. Multi-tenancy is the recommended mode (per-org GitHub
Apps for blast-radius isolation); legacy single-App-many-installs
mode is kept for compatibility.

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/token?org=<org>` | Mint a runner **registration** token for `<org>`. Returns the bare token as `text/plain`. |
| `GET` | `/remove-token?org=<org>` | Mint a runner **removal** token for `<org>`. Same response shape as `/token`. |
| `GET` | `/health` | Liveness probe. Returns `{"status":"healthy"}`. |
| `GET` | `/metrics` | Prometheus exposition (counters + histograms for HTTP / cache / GitHub API). |

If `GITHUB_ORG` is set (or there's only one configured tenant), the
`?org=` parameter can be omitted and the default tenant is used.

## Configuration

### Multi-tenant (recommended)

One GitHub App per org. Each app is created on the org and installed
on its target repos.

```bash
GITHUB_APP_TENANTS="<org1>:<app_id>:<install_id>:<key_path>,<org2>:<app_id>:<install_id>:<key_path>,..."
```

Per-org fields:

| Field | Description |
|---|---|
| `<org>` | GitHub org login (lowercased internally) |
| `<app_id>` | Either the numeric App ID **or** the string Client ID for newer GitHub Apps (e.g. `Iv23liqTIFEtdIu6Vn1r`). GitHub accepts either in the JWT `iss` claim. |
| `<install_id>` | The numeric installation ID for that org |
| `<key_path>` | Filesystem path to the App's private key PEM file |

### Legacy single-tenant (back-compat)

One GitHub App, multiple installations:

```bash
GITHUB_APP_ID=<app id>
GITHUB_APP_INSTALLATIONS=<org1>:<install_id1>,<org2>:<install_id2>,...
GITHUB_APP_PRIVATE_KEY=<inline PEM>           # OR
GITHUB_APP_PRIVATE_KEY_PATH=<path to PEM>
```

`GITHUB_APP_TENANTS` wins if both forms are set.

### Other knobs

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITHUB_ORG` | no | (single-tenant) | Default org when `?org=` is omitted. Must match a configured tenant. |
| `GITHUB_REPO` | no | — | Optional repo-scope; applies under whichever tenant is in play. |
| `TOKEN_SERVER_ADDR` | no | `:8080` | HTTP listen address. |

## Run

### Local (Go)

```bash
mise install
export GITHUB_APP_TENANTS="myorg:123456:7890123:./myorg.pem"
go run .
```

### Container

```bash
docker run --rm \
  -p 8080:8080 \
  -e GITHUB_APP_TENANTS="myorg:123456:7890123:/secrets/myorg.pem" \
  -v $(pwd)/myorg.pem:/secrets/myorg.pem:ro \
  ghcr.io/nkg/gha-token-server:v0.1.0
```

After a tag is pushed, the release workflow publishes multi-arch
images (`linux/amd64` + `linux/arm64`).

## Wiring into gha-nomad-dispatcher

Set the dispatcher's `TOKEN_SERVER_URL` to point at this service.
The dispatcher calls `GET /token?org=<org>` to mint the registration
token it injects into each spawned runner container.

```
# gha-nomad-dispatcher env:
TOKEN_SERVER_URL=http://gha-token-server.lab:8080
```

The two services are designed to sit on the same private network
(VLAN-isolated services tier in the
[terraform-proxmox-fleet](https://github.com/nkg/terraform-proxmox-fleet)
deployment). No mTLS today — the firewall does the authentication
work.

## Design notes

### Cached installation tokens

GitHub's installation access tokens last an hour. We cache per-org
to avoid minting a fresh JWT + hitting `/app/installations/.../access_tokens`
on every runner spawn. Cache keyed on `(org)`.

### Singleflight on cache miss

When N concurrent runner spawns for the same org all miss the
cache, only one JWT + GitHub API call happens — the others wait for
the first. Concurrent misses for **different** orgs run in parallel.
Implemented with `golang.org/x/sync/singleflight`.

### Auth-error invalidation

If GitHub returns 401/403 on a runner-token call, we invalidate the
cached installation token and retry once with a fresh one. Handles
externally-revoked tokens (e.g. App suspended + reinstalled) without
operator intervention.

### Per-tenant key isolation

Each tenant's `*rsa.PrivateKey` is loaded once at startup. Tenants
never share key material in memory — a key leak from one tenant's
code path can't compromise another.

### Numeric vs string App ID

GitHub Apps created on personal accounts after 2024-10-08 (and some
org-owned Apps in the redesigned settings UI) expose only a string
**Client ID** like `Iv23liqTIFEtdIu6Vn1r`, not a numeric App ID.
GitHub's JWT `iss` claim accepts either form, so the tenant's
`AppID` field is a string and passes through verbatim.

### Endpoint shape: GET + text/plain

Both `/token` and `/remove-token` return the bare token as
`text/plain`. That's the simplest possible contract for shell
consumers (the original use case was Ansible / curl). It also
matches what GitHub's own API returns — these endpoints are thin
wrappers around the App installation flow.

## Tests

```bash
go test ./...                 # 14 tests, ~2s
go test -race ./...           # race detector
go test -cover ./...          # coverage
```

Coverage spans config parsing (both formats), JWT generation,
GitHub API mock interaction, multi-tenant routing, per-tenant key
isolation, cache thundering-herd, and the handlers.

## Roadmap

- **v0.2** — `/runner-registration-token` JSON endpoint (alongside the existing text/plain `/token`) so the dispatcher can read `expires_at` and decide whether to mint a fresh one
- **v0.3** — mTLS option for client auth (drop the "firewall does authn" assumption)
- **v0.4** — Token-server own ACL (deny mints from un-authorised callers, not just the network layer)

## License

MIT.
