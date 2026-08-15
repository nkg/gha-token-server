package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hashOf is the value an operator would put in token_sha256.
func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func clientsJSON(t *testing.T, entries []clientFile) string {
	t.Helper()
	b, err := json.Marshal(entries)
	if err != nil {
		t.Fatalf("marshalling clients: %v", err)
	}
	return string(b)
}

// ── parseClients ────────────────────────────────────────────────────

func TestParseClientsInline(t *testing.T) {
	t.Setenv("TOKEN_SERVER_CLIENTS_PATH", "")
	t.Setenv("TOKEN_SERVER_CLIENTS", clientsJSON(t, []clientFile{
		{Name: "ansible", TokenSHA256: hashOf("tok-a"), Orgs: []string{"OrgOne"}},
		{Name: "autoscaler", TokenSHA256: hashOf("tok-b"), Orgs: []string{"*"}},
	}))

	clients, err := parseClients()
	if err != nil {
		t.Fatalf("parseClients() error = %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("got %d clients, want 2", len(clients))
	}

	if clients[0].wildcard {
		t.Error("ansible should not be wildcard")
	}
	// Orgs are lowercased on parse, so an ACL written "OrgOne" still
	// matches the lowercased org the handler resolves.
	if !clients[0].allowedFor("orgone") {
		t.Error("ansible should be allowed for orgone")
	}
	if clients[0].allowedFor("orgtwo") {
		t.Error("ansible must not be allowed for orgtwo")
	}
	if !clients[1].wildcard || !clients[1].allowedFor("anything") {
		t.Error("autoscaler should be wildcard-authorised")
	}
}

func TestParseClientsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "clients.json")
	body := clientsJSON(t, []clientFile{
		{Name: "ansible", TokenSHA256: hashOf("tok-a"), Orgs: []string{"orgone"}},
	})
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing clients file: %v", err)
	}

	// Path wins over inline when both are set.
	t.Setenv("TOKEN_SERVER_CLIENTS_PATH", path)
	t.Setenv("TOKEN_SERVER_CLIENTS", clientsJSON(t, []clientFile{
		{Name: "ignored", TokenSHA256: hashOf("tok-z"), Orgs: []string{"*"}},
	}))

	clients, err := parseClients()
	if err != nil {
		t.Fatalf("parseClients() error = %v", err)
	}
	if len(clients) != 1 || clients[0].Name != "ansible" {
		t.Fatalf("path should win over inline, got %+v", clients)
	}
}

func TestParseClientsUnsetIsEmpty(t *testing.T) {
	t.Setenv("TOKEN_SERVER_CLIENTS_PATH", "")
	t.Setenv("TOKEN_SERVER_CLIENTS", "")

	clients, err := parseClients()
	if err != nil {
		t.Fatalf("parseClients() error = %v", err)
	}
	if len(clients) != 0 {
		t.Fatalf("got %d clients, want 0 — loadConfig decides whether that's fatal", len(clients))
	}
}

func TestParseClientsRejectsBadConfig(t *testing.T) {
	tests := []struct {
		name    string
		entries []clientFile
		raw     string
		wantErr string
	}{
		{
			name:    "missing name",
			entries: []clientFile{{TokenSHA256: hashOf("t"), Orgs: []string{"*"}}},
			wantErr: "name is required",
		},
		{
			name:    "missing token hash",
			entries: []clientFile{{Name: "a", Orgs: []string{"*"}}},
			wantErr: "token_sha256 is required",
		},
		{
			name:    "token hash is not a sha256",
			entries: []clientFile{{Name: "a", TokenSHA256: "deadbeef", Orgs: []string{"*"}}},
			wantErr: "must be 64 hex characters",
		},
		{
			name:    "plaintext token mistakenly used as the hash",
			entries: []clientFile{{Name: "a", TokenSHA256: "my-secret-token", Orgs: []string{"*"}}},
			wantErr: "must be 64 hex characters",
		},
		{
			name:    "missing orgs",
			entries: []clientFile{{Name: "a", TokenSHA256: hashOf("t")}},
			wantErr: "orgs is required",
		},
		{
			name: "duplicate name",
			entries: []clientFile{
				{Name: "a", TokenSHA256: hashOf("t1"), Orgs: []string{"*"}},
				{Name: "a", TokenSHA256: hashOf("t2"), Orgs: []string{"*"}},
			},
			wantErr: "duplicate name",
		},
		{
			name: "two clients sharing one token",
			entries: []clientFile{
				{Name: "a", TokenSHA256: hashOf("same"), Orgs: []string{"*"}},
				{Name: "b", TokenSHA256: hashOf("same"), Orgs: []string{"*"}},
			},
			wantErr: "already used by another client",
		},
		{
			name:    "malformed JSON",
			raw:     "{not json",
			wantErr: "parsing clients JSON",
		},
		{
			name:    "empty array",
			raw:     "[]",
			wantErr: "parsed no entries",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TOKEN_SERVER_CLIENTS_PATH", "")
			raw := tt.raw
			if raw == "" {
				raw = clientsJSON(t, tt.entries)
			}
			t.Setenv("TOKEN_SERVER_CLIENTS", raw)

			_, err := parseClients()
			if err == nil {
				t.Fatalf("parseClients() error = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// ── loadConfig: fail-closed ─────────────────────────────────────────

func TestLoadConfigClients(t *testing.T) {
	key := generateTestKey(t)
	keyPEM := encodePKCS1PEM(key)

	baseEnv := func(t *testing.T) {
		t.Helper()
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_ID", "123")
		t.Setenv("GITHUB_APP_INSTALLATIONS", "myorg:456")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", keyPEM)
	}

	t.Run("refuses to start with no clients and no opt-out", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("TOKEN_SERVER_ALLOW_ANONYMOUS", "")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want a fail-closed error")
		}
		if !strings.Contains(err.Error(), "no clients configured") {
			t.Errorf("error = %q, want it to mention no clients configured", err)
		}
	})

	t.Run("starts with no clients when anonymous is explicitly allowed", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("TOKEN_SERVER_ALLOW_ANONYMOUS", "true")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
		if !cfg.AllowAnonymous {
			t.Error("AllowAnonymous = false, want true")
		}
	})

	t.Run("starts with clients configured", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("TOKEN_SERVER_ALLOW_ANONYMOUS", "")
		t.Setenv("TOKEN_SERVER_CLIENTS", clientsJSON(t, []clientFile{
			{Name: "ansible", TokenSHA256: hashOf("tok"), Orgs: []string{"myorg"}},
		}))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
		if len(cfg.Clients) != 1 || cfg.AllowAnonymous {
			t.Errorf("got %d clients, AllowAnonymous=%v; want 1 and false", len(cfg.Clients), cfg.AllowAnonymous)
		}
	})

	// A typo'd org in an ACL would otherwise be silent: the client
	// would just get 403s for a name that looks correct.
	t.Run("rejects an ACL naming an unconfigured org", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("TOKEN_SERVER_ALLOW_ANONYMOUS", "")
		t.Setenv("TOKEN_SERVER_CLIENTS", clientsJSON(t, []clientFile{
			{Name: "ansible", TokenSHA256: hashOf("tok"), Orgs: []string{"myorg", "typo-org"}},
		}))

		_, err := loadConfig()
		if err == nil {
			t.Fatal("loadConfig() error = nil, want an unknown-tenant error")
		}
		if !strings.Contains(err.Error(), "typo-org") {
			t.Errorf("error = %q, want it to name the offending org", err)
		}
	})

	// A wildcard client is authorised for orgs generally, so it must
	// not be checked against the tenant list.
	t.Run("accepts a wildcard client", func(t *testing.T) {
		baseEnv(t)
		t.Setenv("TOKEN_SERVER_ALLOW_ANONYMOUS", "")
		t.Setenv("TOKEN_SERVER_CLIENTS", clientsJSON(t, []clientFile{
			{Name: "autoscaler", TokenSHA256: hashOf("tok"), Orgs: []string{"*"}},
		}))

		if _, err := loadConfig(); err != nil {
			t.Fatalf("loadConfig() error = %v", err)
		}
	})
}

// ── authenticate ────────────────────────────────────────────────────

func TestAuthenticate(t *testing.T) {
	cfg := &Config{Clients: testClients()}

	tests := []struct {
		name        string
		header      string
		wantClient  string
		wantFailure authFailure
	}{
		{name: "valid bearer", header: "Bearer " + testClientToken, wantClient: "test-client"},
		{name: "scheme is case-insensitive", header: "bearer " + testClientToken, wantClient: "test-client"},
		{name: "no header", header: "", wantFailure: authMissingHeader},
		{name: "wrong scheme", header: "Basic " + testClientToken, wantFailure: authMalformed},
		{name: "no scheme", header: testClientToken, wantFailure: authMalformed},
		{name: "empty credential", header: "Bearer ", wantFailure: authMalformed},
		{name: "unknown token", header: "Bearer nope", wantFailure: authUnknownToken},
		// The stored value is a hash; presenting the hash itself must
		// not authenticate.
		{name: "presenting the hash instead of the token", header: "Bearer " + hashOf(testClientToken), wantFailure: authUnknownToken},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/token", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			client, failure := authenticate(cfg, req)
			if failure != tt.wantFailure {
				t.Fatalf("failure = %q, want %q", failure, tt.wantFailure)
			}
			if tt.wantFailure == "" && client.Name != tt.wantClient {
				t.Errorf("client = %q, want %q", client.Name, tt.wantClient)
			}
		})
	}
}

func TestAuthenticateAnonymousMode(t *testing.T) {
	cfg := &Config{AllowAnonymous: true}

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	client, failure := authenticate(cfg, req)
	if failure != "" {
		t.Fatalf("failure = %q, want none in anonymous mode", failure)
	}
	if client != anonymousClient {
		t.Errorf("client = %+v, want the anonymous sentinel", client)
	}
}

// ── handler enforcement ─────────────────────────────────────────────

// githubStub stands in for the GitHub API so handler tests can reach a
// successful mint.
func githubStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if strings.Contains(r.URL.Path, "access_tokens") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token": "ghs_install", "expires_at": "2099-01-01T00:00:00Z",
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token": "REG-TOKEN", "expires_at": "2099-01-01T00:00:00Z",
		})
	}))
}

func TestTokenHandlerRequiresAuth(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	server := githubStub(t)
	defer server.Close()

	cfg := testConfig(t, server.URL)
	handler := runnerTokenHandler(cfg, "registration")

	t.Run("rejects a request with no credential", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/token", nil))

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") {
			t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
		}
		if strings.Contains(rec.Body.String(), "REG-TOKEN") {
			t.Error("rejected response leaked a token")
		}
	})

	t.Run("rejects an unknown credential", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("accepts a valid credential", func(t *testing.T) {
		resetCache()
		rec := httptest.NewRecorder()
		handler(rec, authed(httptest.NewRequest(http.MethodGet, "/token", nil)))

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); got != "REG-TOKEN" {
			t.Errorf("body = %q, want the minted token", got)
		}
	})
}

func TestTokenHandlerEnforcesOrgACL(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	server := githubStub(t)
	defer server.Close()

	key := generateTestKey(t)
	scoped := &Client{Name: "scoped", orgs: map[string]struct{}{"allowed-org": {}}}
	scoped.tokenHash = sha256.Sum256([]byte("scoped-token"))

	cfg := &Config{
		Tenants: map[string]*Tenant{
			"allowed-org": {Org: "allowed-org", AppID: "1", InstallationID: 1, PrivateKey: key},
			"other-org":   {Org: "other-org", AppID: "2", InstallationID: 2, PrivateKey: key},
		},
		ListenAddr:    ":0",
		githubBaseURL: server.URL,
		Clients:       []*Client{scoped},
	}
	handler := runnerTokenHandler(cfg, "registration")

	do := func(org string) *httptest.ResponseRecorder {
		resetCache()
		req := httptest.NewRequest(http.MethodGet, "/token?org="+org, nil)
		req.Header.Set("Authorization", "Bearer scoped-token")
		rec := httptest.NewRecorder()
		handler(rec, req)
		return rec
	}

	if rec := do("allowed-org"); rec.Code != http.StatusOK {
		t.Errorf("allowed org: status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}

	rec := do("other-org")
	if rec.Code != http.StatusForbidden {
		t.Errorf("unauthorised org: status = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "REG-TOKEN") {
		t.Error("403 response leaked a token")
	}

	// An org this server doesn't serve at all must be indistinguishable
	// from one the client simply isn't authorised for — otherwise the
	// response is an oracle for which orgs exist here.
	unknown := do("no-such-org")
	if unknown.Code != http.StatusForbidden {
		t.Errorf("unknown org: status = %d, want 403 (same as unauthorised)", unknown.Code)
	}
	if unknown.Body.String() != rec.Body.String() {
		t.Errorf("unknown-org body %q differs from unauthorised-org body %q; that distinction leaks which orgs exist",
			unknown.Body.String(), rec.Body.String())
	}
}

// /health and /metrics stay open: probes and Prometheus scrape them,
// and neither exposes org names or token material.
func TestHealthAndMetricsStayUnauthenticated(t *testing.T) {
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	rec := httptest.NewRecorder()
	healthHandler(rec, httptest.NewRequest(http.MethodGet, "/health", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/health status = %d, want 200", rec.Code)
	}

	rec = httptest.NewRecorder()
	metricsHandler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/metrics status = %d, want 200", rec.Code)
	}
}

func TestAuthFailureMetrics(t *testing.T) {
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	server := githubStub(t)
	defer server.Close()

	cfg := testConfig(t, server.URL)
	handler := runnerTokenHandler(cfg, "registration")

	handler(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/token", nil))

	req := httptest.NewRequest(http.MethodGet, "/token", nil)
	req.Header.Set("Authorization", "Bearer nope")
	handler(httptest.NewRecorder(), req)

	rec := httptest.NewRecorder()
	metricsHandler(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()

	for _, want := range []string{
		`token_server_auth_failures_total{reason="missing_header"} 1`,
		`token_server_auth_failures_total{reason="unknown_token"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q\ngot:\n%s", want, body)
		}
	}
}
