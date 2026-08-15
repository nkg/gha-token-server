package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// ── Client authentication ───────────────────────────────────────────
//
// Until now this server had no authentication of its own: anything
// that could reach the port could mint an org-scoped runner
// registration token, which is equivalent to being able to attach a
// runner to the org and collect whatever jobs and secrets it is
// handed. The deployment note said "the firewall does the
// authentication work" — true, but it made the blast radius of any
// misconfigured route or forwarded port total.
//
// Callers now present a bearer token. Each configured client is a
// named credential with an explicit list of orgs it may mint for, so
// a leaked Ansible credential can't mint for an unrelated tenant.

// Client is one authorised caller.
type Client struct {
	// Name identifies the caller in logs. Not a secret.
	Name string

	// tokenHash is the SHA-256 of the caller's bearer token. Only the
	// hash is configured, so the deployed config never carries a
	// credential that would work if read.
	tokenHash [32]byte

	// orgs is the set of orgs this client may mint for, lowercased.
	// Ignored when wildcard is true.
	orgs map[string]struct{}

	// wildcard is true when the client is authorised for every
	// configured tenant (`"orgs": ["*"]`).
	wildcard bool
}

// allowedFor reports whether this client may mint for org.
func (c *Client) allowedFor(org string) bool {
	if c.wildcard {
		return true
	}
	_, ok := c.orgs[org]
	return ok
}

// anonymousClient stands in for the caller when authentication is
// disabled via TOKEN_SERVER_ALLOW_ANONYMOUS. It is authorised for
// everything — that is the whole point of the escape hatch — but it
// is a distinct value so logs and metrics don't silently look like an
// authenticated mint.
var anonymousClient = &Client{Name: "anonymous", wildcard: true}

// ── Config parsing ──────────────────────────────────────────────────

// clientFile is the on-disk/inline JSON shape for one client.
type clientFile struct {
	Name        string   `json:"name"`
	TokenSHA256 string   `json:"token_sha256"`
	Orgs        []string `json:"orgs"`
}

// parseClients builds the authorised-caller list from environment.
//
// Preferred form is a file, since the deploying composition already
// renders SOPS-decrypted material to disk:
//
//	TOKEN_SERVER_CLIENTS_PATH=/etc/token-server/clients.json
//
// Inline JSON is also accepted for container deployments that would
// rather pass one env var than mount a file:
//
//	TOKEN_SERVER_CLIENTS='[{"name":"ansible","token_sha256":"…","orgs":["myorg"]}]'
//
// The path wins if both are set. Returns an empty slice when neither
// is configured — loadConfig decides whether that is fatal.
func parseClients() ([]*Client, error) {
	var raw []byte

	if path := strings.TrimSpace(os.Getenv("TOKEN_SERVER_CLIENTS_PATH")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading TOKEN_SERVER_CLIENTS_PATH %s: %w", path, err)
		}
		raw = data
	} else if inline := strings.TrimSpace(os.Getenv("TOKEN_SERVER_CLIENTS")); inline != "" {
		raw = []byte(inline)
	} else {
		return nil, nil
	}

	var entries []clientFile
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("parsing clients JSON: %w", err)
	}

	out := make([]*Client, 0, len(entries))
	seenName := map[string]struct{}{}
	seenHash := map[string]struct{}{}

	for i, e := range entries {
		name := strings.TrimSpace(e.Name)
		if name == "" {
			return nil, fmt.Errorf("clients[%d]: name is required", i)
		}
		if _, dup := seenName[name]; dup {
			return nil, fmt.Errorf("clients[%d]: duplicate name %q", i, name)
		}
		seenName[name] = struct{}{}

		hexHash := strings.ToLower(strings.TrimSpace(e.TokenSHA256))
		if hexHash == "" {
			return nil, fmt.Errorf("clients[%d] (%s): token_sha256 is required", i, name)
		}
		decoded, err := hex.DecodeString(hexHash)
		if err != nil || len(decoded) != sha256.Size {
			return nil, fmt.Errorf(
				"clients[%d] (%s): token_sha256 must be %d hex characters (a SHA-256 digest), got %q",
				i, name, sha256.Size*2, e.TokenSHA256)
		}
		if _, dup := seenHash[hexHash]; dup {
			return nil, fmt.Errorf("clients[%d] (%s): token_sha256 is already used by another client", i, name)
		}
		seenHash[hexHash] = struct{}{}

		if len(e.Orgs) == 0 {
			return nil, fmt.Errorf("clients[%d] (%s): orgs is required (use [\"*\"] for all)", i, name)
		}

		c := &Client{Name: name, orgs: map[string]struct{}{}}
		copy(c.tokenHash[:], decoded)
		for _, org := range e.Orgs {
			org = strings.ToLower(strings.TrimSpace(org))
			if org == "*" {
				c.wildcard = true
				continue
			}
			if org == "" {
				return nil, fmt.Errorf("clients[%d] (%s): empty org in list", i, name)
			}
			c.orgs[org] = struct{}{}
		}
		if !c.wildcard && len(c.orgs) == 0 {
			return nil, fmt.Errorf("clients[%d] (%s): orgs contained no usable entries", i, name)
		}
		out = append(out, c)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("clients configuration is set but parsed no entries")
	}
	return out, nil
}

// ── Request authentication ──────────────────────────────────────────

// authFailure describes why a request was rejected, and doubles as
// the `reason` metric label. Deliberately coarse: the response never
// tells the caller which of these applied, so an attacker can't use
// the distinction to enumerate valid tokens or orgs.
type authFailure string

const (
	authMissingHeader authFailure = "missing_header"
	authMalformed     authFailure = "malformed_header"
	authUnknownToken  authFailure = "unknown_token"
	authOrgDenied     authFailure = "org_denied"
)

// authenticate resolves the bearer token on the request to a
// configured client.
//
// Every configured client is compared in constant time and the
// comparison is not short-circuited on the first match, so the time
// taken doesn't reveal how far down the list a token sits — or, for a
// non-matching token, how many clients are configured.
func authenticate(cfg *Config, r *http.Request) (*Client, authFailure) {
	if cfg.AllowAnonymous {
		return anonymousClient, ""
	}

	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, authMissingHeader
	}

	// Scheme is case-insensitive per RFC 7235.
	scheme, presented, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return nil, authMalformed
	}
	presented = strings.TrimSpace(presented)
	if presented == "" {
		return nil, authMalformed
	}

	sum := sha256.Sum256([]byte(presented))

	var matched *Client
	for _, c := range cfg.Clients {
		if subtle.ConstantTimeCompare(sum[:], c.tokenHash[:]) == 1 {
			matched = c
		}
	}
	if matched == nil {
		return nil, authUnknownToken
	}
	return matched, ""
}

// writeAuthFailure sends the response for a rejected request.
//
// The body is deliberately uniform: a caller learns that it was
// refused, never whether the token was unrecognised or merely not
// authorised for the org it asked about. Distinguishing them would
// let an unauthenticated prober enumerate which orgs this server
// serves.
func writeAuthFailure(w http.ResponseWriter, reason authFailure) {
	if metrics != nil {
		metrics.recordAuthFailure(reason)
	}
	switch reason {
	case authOrgDenied:
		http.Error(w, "forbidden", http.StatusForbidden)
	default:
		w.Header().Set("WWW-Authenticate", `Bearer realm="gha-token-server"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}
