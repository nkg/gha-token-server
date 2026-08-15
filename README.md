# gha-token-server

GitHub App backed token-minting service for self-hosted GitHub
Actions runners. Multi-tenant (one or more orgs per server), cached
installation tokens with thundering-herd protection, Prometheus
metrics, JSON structured logs.

A standalone service for any client that needs short-lived runner
tokens — Ansible, CI plumbing, custom autoscalers. Note that
[nkg/gha-nomad-dispatcher](https://github.com/nkg/gha-nomad-dispatcher)
folded this logic in as of its v0.2 and no longer calls this service;
see "Relationship to gha-nomad-dispatcher" below.

Lifted from a working internal deployment. It ran as its own LXC in
the nkg homelab until `gha-nomad-dispatcher` v0.2 folded the minting
logic in; it is **no longer deployed there** (see below). The code is
maintained and released regardless, for non-Nomad consumers.

Multi-tenancy is the recommended mode (per-org GitHub Apps for
blast-radius isolation); legacy single-App-many-installs mode is kept
for compatibility.

## Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/token?org=<org>` | **required** | Mint a runner **registration** token for `<org>`. Returns the bare token as `text/plain`. |
| `GET` | `/remove-token?org=<org>` | **required** | Mint a runner **removal** token for `<org>`. Same response shape as `/token`. |
| `GET` | `/health` | open | Liveness probe. Returns `{"status":"healthy"}`. |
| `GET` | `/metrics` | open | Prometheus exposition (counters + histograms for HTTP / cache / GitHub API / auth failures). |

If `GITHUB_ORG` is set (or there's only one configured tenant), the
`?org=` parameter can be omitted and the default tenant is used.

`/health` and `/metrics` are deliberately unauthenticated — probes and
Prometheus need them, and neither exposes org names or token material.

## Authentication

Minting a runner registration token is equivalent to being able to
attach a runner to the org, and therefore to collect whatever jobs and
secrets that org hands out. Callers must present a bearer token:

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "https://token-server.lab:8080/token?org=myorg"
```

### Configuring clients

Each client is a named credential with an explicit list of orgs it may
mint for. Only the **SHA-256 of the token** is configured, so the
deployed config never carries a credential that would work if read.

```bash
# Generate a token and its hash. Keep the token; configure the hash.
TOKEN=$(openssl rand -hex 32)
echo "token: $TOKEN"
echo "hash:  $(printf '%s' "$TOKEN" | sha256sum | cut -d' ' -f1)"
```

> Use `printf '%s'`, not `echo` — a trailing newline changes the
> digest and you'll get a 401 that looks inexplicable.

```json
[
  { "name": "ansible-provisioner", "token_sha256": "<64 hex chars>", "orgs": ["myorg"] },
  { "name": "nkg-autoscaler",      "token_sha256": "<64 hex chars>", "orgs": ["*"]     }
]
```

See `clients.example.json`. Its placeholders are deliberately not
valid digests, so starting with it unedited fails immediately with a
message naming the offending field rather than silently accepting a
credential nobody holds.

| Field | Description |
|---|---|
| `name` | Identifies the caller in logs and audit lines. Not a secret. |
| `token_sha256` | 64 hex characters. The SHA-256 of the bearer token. |
| `orgs` | Orgs this client may mint for. `["*"]` authorises every tenant. |

Point the server at it:

```bash
TOKEN_SERVER_CLIENTS_PATH=/etc/token-server/clients.json   # preferred
TOKEN_SERVER_CLIENTS='[{"name":"…","token_sha256":"…","orgs":["…"]}]'  # inline alternative
```

The path wins if both are set. The file form suits the SOPS-rendered
deployment; the inline form suits a container that would rather pass
one env var than mount a file.

Config is validated at startup and the server refuses to start on:
a `token_sha256` that isn't a SHA-256 digest (which catches pasting
the plaintext token in by mistake), two clients sharing a token,
duplicate names, an empty `orgs`, or an ACL naming an org that isn't
a configured tenant — a typo there would otherwise show up only as
403s against a name that looks correct.

### Responses

| Status | Meaning |
|---|---|
| `401` | No credential, a malformed `Authorization` header, or an unrecognised token. Carries a `WWW-Authenticate: Bearer` challenge. |
| `403` | Valid credential, but not authorised for the requested org. |

`403` is returned both when the client isn't authorised for an org and
when that org isn't configured here at all, with an identical body.
Distinguishing them would let any caller holding one valid credential
enumerate which orgs this server serves.

### Running without authentication

```bash
TOKEN_SERVER_ALLOW_ANONYMOUS=true
```

Restores the old behaviour: any caller that can reach the port can
mint for any configured org. The server logs a `WARN` on every start
in this mode.

It exists so the binary can be rolled out before every caller has been
issued a credential. **Without it, and with no clients configured, the
server refuses to start** — an unauthenticated token minter is not a
safe default, firewall or not.

### Migrating an existing deployment

Not applicable to the nkg homelab — nothing is deployed, so there are
no callers to migrate. Kept for anyone who *is* running this: the
fail-closed default is a breaking change for existing callers.

1. Deploy with `TOKEN_SERVER_ALLOW_ANONYMOUS=true`. Nothing changes for
   existing callers.
2. Mint a token per caller, configure the hashes, and update each
   caller to send the `Authorization` header.
3. Watch `token_server_auth_failures_total` — while anonymous mode is
   on it stays at zero, so first confirm each caller works by pointing
   a test instance without the flag at the same config.
4. Drop `TOKEN_SERVER_ALLOW_ANONYMOUS` and restart. Any caller you
   missed now gets a `401`, visible in both the metric and the logs.

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
| `TOKEN_SERVER_CLIENTS_PATH` | yes\* | — | Path to the clients JSON. See [Authentication](#authentication). |
| `TOKEN_SERVER_CLIENTS` | yes\* | — | Inline clients JSON. `TOKEN_SERVER_CLIENTS_PATH` wins if both are set. |
| `TOKEN_SERVER_ALLOW_ANONYMOUS` | no | `false` | `true` disables caller authentication entirely. |

\* One of the two is required unless `TOKEN_SERVER_ALLOW_ANONYMOUS=true`.

## Run

### Local (Go)

```bash
mise install
export GITHUB_APP_TENANTS="myorg:123456:7890123:./myorg.pem"
export TOKEN_SERVER_CLIENTS_PATH=./clients.json
go run .
```

For a throwaway local run without setting up credentials:

```bash
export TOKEN_SERVER_ALLOW_ANONYMOUS=true
go run .
```

### Container

```bash
docker run --rm \
  -p 8080:8080 \
  -e GITHUB_APP_TENANTS="myorg:123456:7890123:/secrets/myorg.pem" \
  -e TOKEN_SERVER_CLIENTS_PATH=/secrets/clients.json \
  -v $(pwd)/myorg.pem:/secrets/myorg.pem:ro \
  -v $(pwd)/clients.json:/secrets/clients.json:ro \
  ghcr.io/nkg/gha-token-server:v0.1.0
```

After a tag is pushed, the release workflow publishes multi-arch
images (`linux/amd64` + `linux/arm64`).

## Relationship to gha-nomad-dispatcher

**The dispatcher no longer calls this service.** As of its v0.2 it
mints tokens in-process (`internal/github`), which drops one LXC and
one secrets-distribution hop, and keeps the App private keys in a
single place. Don't expect a `TOKEN_SERVER_URL` knob over there —
it's gone.

This server remains useful for consumers that aren't the dispatcher:
Ansible plays, ad-hoc `curl` from a provisioning script, custom
autoscalers, or anything that wants a runner token without embedding
GitHub App credentials. It's also the only one of the two that mints
**removal** tokens, which `oci-actions-runner` needs for
`RUNNER_REMOVE_TOKEN` when running non-ephemeral runners.

**Not currently deployed anywhere.** The nkg homelab's CI platform
decided against it — see platform ADR-019, which records the Nomad
runner design and concludes: *"`nkg/gha-token-server` is now redundant
… no action, but don't deploy it for this platform."* An earlier
version of this README claimed it ran on the fleet's services tier;
that was aspirational and never true.

So there is no migration to do for the caller-authentication change
below: there are no existing callers to issue credentials to. Anyone
adopting this service starts with clients configured from the outset.

If you do deploy it: callers authenticate with a bearer token and are
scoped to specific orgs, so a firewall becomes defence in depth rather
than the only control. There's still no mTLS — the credential is a
shared secret in transit, so keep it on a private network or put TLS
in front of it.

## Verifying a release

Released images are signed with [cosign](https://docs.sigstore.dev/)
keyless OIDC, and carry an SPDX SBOM plus SLSA build provenance as
in-toto attestations. There is no long-lived signing key — the
signature is bound to the GitHub Actions workflow that produced the
image.

```bash
IMAGE=ghcr.io/nkg/gha-token-server:<tag>

# Signature. The identity regexp is what makes this meaningful:
# it asserts the image was built by *this* repo's workflow, not
# merely that someone signed it.
cosign verify "$IMAGE" \
  --certificate-identity-regexp '^https://github.com/nkg/gha-token-server/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'

# Build provenance (what built it, from which commit)
gh attestation verify "oci://$IMAGE" --repo nkg/gha-token-server

# SBOM
cosign download sbom "$IMAGE"
```

Signatures bind the **digest**, not the tag — a tag can be moved, a
digest cannot. Pin by digest in production if you want the guarantee
to hold over time.

## Design notes

### Why bearer tokens rather than mTLS

The roadmap originally had mTLS. The consumers here are Ansible plays,
shell scripts and small autoscalers, where adding a header is one line
and issuing, distributing and rotating a client certificate per caller
is a standing operational cost. Bearer tokens also carry the caller's
*identity* naturally, which is what the per-org ACL needs — mTLS would
have required mapping certificate subjects to orgs to get the same
thing. mTLS remains on the roadmap as an alternative for deployments
that would rather not hold a shared secret at each caller.

### Only hashes are configured

The clients file holds `token_sha256`, never the token. Reading the
deployed config — or a backup of it, or a SOPS decryption during
review — doesn't yield anything that authenticates. Startup rejects a
`token_sha256` that isn't 64 hex characters, which is what catches
the natural mistake of pasting the plaintext token into that field.

### Constant-time comparison, no short-circuit

Every configured client is compared with `subtle.ConstantTimeCompare`
and the loop does **not** break on the first match. Breaking early
would make the response time depend on how far down the list a token
sits, and for a non-matching token, on how many clients are
configured.

### Failure responses don't leak topology

`401` covers "no credential", "malformed header" and "unknown token"
with one body; `403` covers both "not authorised for this org" and
"no such org here". The `reason` is recorded in the metric and the
log, where the operator can see it, but never in the response — a
caller shouldn't be able to use the difference to enumerate valid
tokens or discover which orgs this server serves.

### Auth failures are a metric, not just a log line

`token_server_auth_failures_total{reason}` is worth alerting on: a
rising `unknown_token` is someone probing the port, and a rising
`missing_header` after a rollout is usually a caller that was missed
in the migration.

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
go test ./...                 # ~2s
go test -race ./...           # race detector
go test -cover ./...          # coverage
```

Coverage spans config parsing (both formats), JWT generation,
GitHub API mock interaction, multi-tenant routing, per-tenant key
isolation, cache thundering-herd, the metrics histogram, and the
handlers.

Auth coverage is in `auth_test.go`: client-config parsing and its
rejections, the fail-closed startup rule, bearer parsing (including
that presenting the stored *hash* does not authenticate), org-ACL
enforcement, and that an unauthorised org is indistinguishable from
an unconfigured one. The behaviour tests present a real credential
rather than enabling anonymous mode, so they exercise the
authenticated path that runs in production.

## Roadmap

- **v0.2** — `/runner-registration-token` JSON endpoint (alongside the existing text/plain `/token`) so the dispatcher can read `expires_at` and decide whether to mint a fresh one
- ~~**v0.3** — mTLS option for client auth (drop the "firewall does authn" assumption)~~ — **partly done**: bearer-token authn landed, so the "firewall does authn" assumption is gone. mTLS itself is still open; see below.
- ~~**v0.4** — Token-server own ACL (deny mints from un-authorised callers, not just the network layer)~~ — **done**: per-client org ACLs, enforced before the tenant lookup.
- **mTLS** — client certificates as an alternative to bearer tokens, for deployments that would rather not hold a shared secret at each caller. Bearer tokens were chosen first because the consumers here are Ansible and shell scripts, where a header is trivial and cert distribution and rotation is not.
- **Token rotation** — support two valid hashes per client so a credential can be rolled without a flag-day restart.

## License

MIT.
