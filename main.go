package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/sync/singleflight"
)

// authError indicates a GitHub API authentication failure.
type authError struct {
	statusCode int
	body       string
}

func (e *authError) Error() string {
	return fmt.Sprintf("GitHub API returned %d: %s", e.statusCode, e.body)
}

// isAuthError checks if an error is an authentication-related failure.
func isAuthError(err error) bool {
	var ae *authError
	if errors.As(err, &ae) {
		return ae.statusCode == http.StatusUnauthorized || ae.statusCode == http.StatusForbidden
	}
	return false
}

// Tenant holds the credentials for a single org's GitHub App installation.
//
// Under the multi-tenant model (Option B in the design discussion), each org
// owns its own GitHub App with its own App ID (or Client ID), installation
// ID, and private key — so this struct carries everything needed to mint
// tokens for one org in isolation.
//
// AppID is a string because newer GitHub Apps (created on personal accounts
// after 2024-10-08, and some org-owned Apps in the redesigned settings UI)
// only expose a string Client ID like "Iv23liqTIFEtdIu6Vn1r" — not a numeric
// App ID. GitHub's JWT `iss` claim accepts either form, so we pass whatever
// the operator configured straight through.
type Tenant struct {
	Org            string // lowercased
	AppID          string // numeric App ID or string Client ID — used as JWT issuer verbatim
	InstallationID int64
	PrivateKey     *rsa.PrivateKey
}

// Config holds the server configuration loaded from environment variables.
//
// Each org served by the server runs as its own tenant with its own GitHub
// App credentials. See parseTenants for the env-var schema (preferred
// `GITHUB_APP_TENANTS=...`, plus a legacy single-App fallback for
// existing single-tenant deployments).
type Config struct {
	Tenants       map[string]*Tenant // lowercased org → tenant
	DefaultOrg    string             // used when ?org= query param is omitted
	GitHubRepo    string             // optional repo-scope; applies under whichever tenant is in play
	ListenAddr    string
	githubBaseURL string
}

// tokenCache caches installation access tokens, keyed by lowercased org name.
//
// Concurrency model:
//   - The mutex is held only for fast map ops (lookup / store / delete).
//   - Cache misses dispatch through a singleflight.Group keyed by org so
//     concurrent callers for the SAME org coalesce into a single GitHub API
//     call (the original thundering-herd guard) while concurrent callers
//     for DIFFERENT orgs run in parallel.
//   - Net effect: one slow refresh for org A doesn't stall org B's
//     callers — important once the server became multi-tenant.
type tokenCache struct {
	mu      sync.Mutex
	entries map[string]tokenCacheEntry
	flight  singleflight.Group
}

type tokenCacheEntry struct {
	token     string
	expiresAt time.Time
}

var cache = tokenCache{entries: map[string]tokenCacheEntry{}}

// invalidateTokenCache clears the cached installation token for a specific
// org. Called when a downstream API call fails with an auth error,
// indicating the cached token may have been revoked externally.
func invalidateTokenCache(org string) {
	cache.mu.Lock()
	delete(cache.entries, org)
	cache.mu.Unlock()
	slog.Info("invalidated cached installation token", "org", org)
}

// httpClient is a shared HTTP client with timeout for outgoing requests.
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
}

// ── Prometheus Metrics ──────────────────────────────────────────────

type serverMetrics struct {
	mu sync.Mutex

	// Counter: total HTTP requests by endpoint and status code
	httpRequestsTotal map[string]map[int]int64

	// Histogram: request duration by endpoint
	httpDurationBuckets []float64
	httpDurationObs     map[string][]float64 // endpoint -> observed durations

	// Counters
	cacheHits       atomic.Int64
	cacheMisses     atomic.Int64
	githubAPIErrors map[string]int64 // operation -> count
}

func newServerMetrics() *serverMetrics {
	return &serverMetrics{
		httpRequestsTotal:   make(map[string]map[int]int64),
		httpDurationBuckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30},
		httpDurationObs:     make(map[string][]float64),
		githubAPIErrors:     make(map[string]int64),
	}
}

func (m *serverMetrics) recordRequest(endpoint string, statusCode int, duration time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.httpRequestsTotal[endpoint] == nil {
		m.httpRequestsTotal[endpoint] = make(map[int]int64)
	}
	m.httpRequestsTotal[endpoint][statusCode]++

	m.httpDurationObs[endpoint] = append(m.httpDurationObs[endpoint], duration.Seconds())
}

func (m *serverMetrics) recordGitHubAPIError(operation string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.githubAPIErrors[operation]++
}

var metrics *serverMetrics

// ── Main ────────────────────────────────────────────────────────────

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := loadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}

	metrics = newServerMetrics()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", instrumentHandler("/token", runnerTokenHandler(cfg, "registration")))
	mux.HandleFunc("/remove-token", instrumentHandler("/remove-token", runnerTokenHandler(cfg, "remove")))
	mux.HandleFunc("/health", instrumentHandler("/health", healthHandler))
	mux.HandleFunc("/metrics", metricsHandler) // not instrumented to avoid feedback loop

	slog.Info("starting token server",
		"addr", cfg.ListenAddr,
		"tenants", len(cfg.Tenants),
		"default_org", cfg.DefaultOrg,
	)
	for org, tenant := range cfg.Tenants {
		if cfg.GitHubRepo != "" {
			slog.Info("tenant registered",
				"org", org,
				"app_id", tenant.AppID,
				"installation_id", tenant.InstallationID,
				"repo_scope", cfg.GitHubRepo)
		} else {
			slog.Info("tenant registered",
				"org", org,
				"app_id", tenant.AppID,
				"installation_id", tenant.InstallationID)
		}
	}

	server := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 65 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in background goroutine
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or server error
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig.String())
	case err := <-errCh:
		slog.Error("server failed", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown with 10s timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("shutdown error", "error", err)
		os.Exit(1)
	}
	slog.Info("server stopped gracefully")
}

// ── Config ──────────────────────────────────────────────────────────

func loadConfig() (*Config, error) {
	tenants, err := parseTenants()
	if err != nil {
		return nil, err
	}

	defaultOrg := strings.ToLower(os.Getenv("GITHUB_ORG"))
	if defaultOrg != "" {
		if _, ok := tenants[defaultOrg]; !ok {
			return nil, fmt.Errorf("GITHUB_ORG=%q is not in configured tenants", defaultOrg)
		}
	} else if len(tenants) == 1 {
		// Single-tenant mode: that one is the default.
		for org := range tenants {
			defaultOrg = org
		}
	}

	listenAddr := os.Getenv("TOKEN_SERVER_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}

	return &Config{
		Tenants:       tenants,
		DefaultOrg:    defaultOrg,
		GitHubRepo:    os.Getenv("GITHUB_REPO"),
		ListenAddr:    listenAddr,
		githubBaseURL: "https://api.github.com",
	}, nil
}

// parseTenants builds the org → Tenant map from environment.
//
// Preferred form (per-org App, "Option B"):
//
//	GITHUB_APP_TENANTS=org1:app_id:installation_id:key_path,org2:...,...
//
// Each org carries its own App ID, installation ID, and private-key file
// path. Use this when each org should have an identity-isolated App
// (per-org audit attribution, per-org key rotation, blast-radius
// isolation).
//
// Legacy form (one App, many installations — "Option A"):
//
//	GITHUB_APP_ID=<single app id>
//	GITHUB_APP_INSTALLATIONS=org1:install_id1,org2:install_id2,...
//	GITHUB_APP_PRIVATE_KEY=<inline PEM>  OR  GITHUB_APP_PRIVATE_KEY_PATH=<path>
//
// Builds a synthetic tenant map where every org points at the same App
// ID + key. Existing single-App deployments keep working unchanged.
//
// `GITHUB_APP_TENANTS` wins if both are set.
func parseTenants() (map[string]*Tenant, error) {
	raw := strings.TrimSpace(os.Getenv("GITHUB_APP_TENANTS"))
	if raw != "" {
		return parseTenantsCSV(raw)
	}
	return parseLegacyTenants()
}

func parseTenantsCSV(raw string) (map[string]*Tenant, error) {
	out := map[string]*Tenant{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// SplitN with limit 4 so any colons within key_path (e.g. a
		// Windows-style "C:\\path\\to\\key.pem", or a niche POSIX path
		// that happens to contain a colon) end up inside parts[3]
		// rather than splitting it across parts. The first three
		// fields are guaranteed colon-free by construction (org is a
		// GitHub login; app_id is a numeric ID or a string Client ID
		// like Iv23..., both colon-free; installation_id is integer),
		// so the lenient split is safe.
		parts := strings.SplitN(entry, ":", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: entry %q must be org:app_id:installation_id:key_path", entry)
		}
		org := strings.ToLower(strings.TrimSpace(parts[0]))
		if org == "" {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: entry %q has empty org", entry)
		}
		appID := strings.TrimSpace(parts[1])
		if appID == "" {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: %s app_id is empty", org)
		}
		installationID, err := strconv.ParseInt(strings.TrimSpace(parts[2]), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: %s installation_id %q is not a number: %w", org, parts[2], err)
		}
		keyPath := strings.TrimSpace(parts[3])
		if keyPath == "" {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: %s key_path is empty", org)
		}
		key, err := loadPrivateKeyFromPath(keyPath)
		if err != nil {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: %s: %w", org, err)
		}
		if _, dup := out[org]; dup {
			return nil, fmt.Errorf("GITHUB_APP_TENANTS: duplicate org %q", org)
		}
		out[org] = &Tenant{
			Org:            org,
			AppID:          appID,
			InstallationID: installationID,
			PrivateKey:     key,
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("GITHUB_APP_TENANTS is set but parsed no entries")
	}
	return out, nil
}

// parseLegacyTenants supports the single-App-many-installations layout the
// server was originally built for. Returns a tenant map where every entry
// shares the same App ID and private key.
func parseLegacyTenants() (map[string]*Tenant, error) {
	appID := strings.TrimSpace(os.Getenv("GITHUB_APP_ID"))
	if appID == "" {
		return nil, fmt.Errorf("set GITHUB_APP_TENANTS=org:app_id:install_id:key_path,... " +
			"or the legacy GITHUB_APP_ID + GITHUB_APP_INSTALLATIONS + GITHUB_APP_PRIVATE_KEY combo")
	}

	key, err := loadPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	installations, err := parseLegacyInstallations()
	if err != nil {
		return nil, err
	}

	out := make(map[string]*Tenant, len(installations))
	for org, installID := range installations {
		out[org] = &Tenant{
			Org:            org,
			AppID:          appID,
			InstallationID: installID,
			PrivateKey:     key,
		}
	}
	return out, nil
}

// parseLegacyInstallations parses the legacy `GITHUB_APP_INSTALLATIONS=org:id,...`
// env var, falling back to the single-installation `GITHUB_ORG +
// GITHUB_APP_INSTALLATION_ID` pair if it's absent.
func parseLegacyInstallations() (map[string]int64, error) {
	raw := strings.TrimSpace(os.Getenv("GITHUB_APP_INSTALLATIONS"))
	if raw != "" {
		out := map[string]int64{}
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			org, idStr, ok := strings.Cut(pair, ":")
			if !ok {
				return nil, fmt.Errorf("GITHUB_APP_INSTALLATIONS: entry %q must be org:id", pair)
			}
			org = strings.ToLower(strings.TrimSpace(org))
			idStr = strings.TrimSpace(idStr)
			if org == "" {
				return nil, fmt.Errorf("GITHUB_APP_INSTALLATIONS: entry %q has empty org", pair)
			}
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("GITHUB_APP_INSTALLATIONS: %s installation id %q is not a number: %w", org, idStr, err)
			}
			if _, dup := out[org]; dup {
				return nil, fmt.Errorf("GITHUB_APP_INSTALLATIONS: duplicate org %q", org)
			}
			out[org] = id
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("GITHUB_APP_INSTALLATIONS is set but parsed no entries")
		}
		return out, nil
	}

	// Back-compat single-installation path.
	org := strings.ToLower(os.Getenv("GITHUB_ORG"))
	idStr := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	if org == "" || idStr == "" {
		return nil, fmt.Errorf("set GITHUB_APP_INSTALLATIONS=org1:id1,... or both GITHUB_ORG and GITHUB_APP_INSTALLATION_ID")
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("GITHUB_APP_INSTALLATION_ID must be a number: %w", err)
	}
	return map[string]int64{org: id}, nil
}

// loadPrivateKey reads the legacy single-key env vars
// (GITHUB_APP_PRIVATE_KEY_PATH or GITHUB_APP_PRIVATE_KEY). Used by the
// legacy Option A code path only — per-tenant keys use
// loadPrivateKeyFromPath directly.
func loadPrivateKey() (*rsa.PrivateKey, error) {
	keyPath := os.Getenv("GITHUB_APP_PRIVATE_KEY_PATH")
	if keyPath != "" {
		return loadPrivateKeyFromPath(keyPath)
	}
	keyPEM := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	if keyPEM == "" {
		return nil, fmt.Errorf("GITHUB_APP_PRIVATE_KEY_PATH or GITHUB_APP_PRIVATE_KEY is required")
	}
	return parsePrivateKeyPEM([]byte(keyPEM))
}

func loadPrivateKeyFromPath(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file %s: %w", path, err)
	}
	return parsePrivateKeyPEM(data)
}

func parsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block from private key")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse private key (tried PKCS1 and PKCS8): %w", err)
		}
		rsaKey, ok := pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
		return rsaKey, nil
	}

	return key, nil
}

// ── JWT & GitHub API ────────────────────────────────────────────────

// generateJWT creates a signed JWT for the given tenant's GitHub App.
// Each tenant signs with its own AppID + private key.
func generateJWT(tenant *Tenant) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
		Issuer:    tenant.AppID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(tenant.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	return signed, nil
}

// doRequestWithRetry executes an HTTP request with a single retry on network errors or 5xx.
func doRequestWithRetry(method, url string, headers map[string]string) (*http.Response, []byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(1 * time.Second)
		}

		req, err := http.NewRequest(method, url, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("creating request: %w", err)
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("executing request: %w", err)
			slog.Warn("request failed, will retry", "url", url, "attempt", attempt+1, "error", err)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, nil, fmt.Errorf("reading response body: %w", err)
		}

		// Retry on 5xx
		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
			slog.Warn("server error, will retry", "url", url, "status", resp.StatusCode, "attempt", attempt+1)
			continue
		}

		return resp, body, nil
	}

	return nil, nil, lastErr
}

// getInstallationToken fetches (or returns cached) installation access token
// for the given tenant.
//
// Cache lookups take only the map lock — they don't block waiting for any
// in-flight GitHub API call. Misses go through singleflight keyed by org
// name, so concurrent callers for the same tenant share one upstream fetch
// (the original thundering-herd guard) while concurrent callers for
// different tenants refresh in parallel.
func getInstallationToken(cfg *Config, tenant *Tenant) (string, error) {
	// Fast path: cache hit doesn't need to wait on any in-flight refresh.
	cache.mu.Lock()
	entry, ok := cache.entries[tenant.Org]
	cache.mu.Unlock()
	if ok && entry.token != "" && time.Now().Before(entry.expiresAt.Add(-5*time.Minute)) {
		if metrics != nil {
			metrics.cacheHits.Add(1)
		}
		return entry.token, nil
	}

	if metrics != nil {
		metrics.cacheMisses.Add(1)
	}

	v, err, _ := cache.flight.Do(tenant.Org, func() (any, error) {
		// Re-check the cache under singleflight: a concurrent caller may
		// have refreshed between our miss observation and entering Do.
		cache.mu.Lock()
		if e, ok := cache.entries[tenant.Org]; ok && e.token != "" && time.Now().Before(e.expiresAt.Add(-5*time.Minute)) {
			cache.mu.Unlock()
			return e.token, nil
		}
		cache.mu.Unlock()

		jwtToken, err := generateJWT(tenant)
		if err != nil {
			return "", err
		}

		url := fmt.Sprintf("%s/app/installations/%d/access_tokens", cfg.githubBaseURL, tenant.InstallationID)
		headers := map[string]string{
			"Authorization": "Bearer " + jwtToken,
			"Accept":        "application/vnd.github.v3+json",
			"User-Agent":    "github-app-token-server",
		}

		resp, body, err := doRequestWithRetry("POST", url, headers)
		if err != nil {
			if metrics != nil {
				metrics.recordGitHubAPIError("get_installation_token")
			}
			return "", fmt.Errorf("requesting installation token: %w", err)
		}

		if resp.StatusCode != http.StatusCreated {
			if metrics != nil {
				metrics.recordGitHubAPIError("get_installation_token")
			}
			return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
		}

		var result struct {
			Token     string    `json:"token"`
			ExpiresAt time.Time `json:"expires_at"`
		}
		if err := json.Unmarshal(body, &result); err != nil {
			return "", fmt.Errorf("parsing response: %w", err)
		}

		cache.mu.Lock()
		cache.entries[tenant.Org] = tokenCacheEntry{
			token:     result.Token,
			expiresAt: result.ExpiresAt,
		}
		cache.mu.Unlock()

		slog.Info("obtained new installation token",
			"org", tenant.Org,
			"installation_id", tenant.InstallationID,
			"expires_at", result.ExpiresAt.Format(time.RFC3339))
		return result.Token, nil
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

// getRunnerToken exchanges the installation token for a runner registration or
// removal token. kind is "registration" or "remove" — it controls both the
// GitHub API URL suffix and the metric label. org is the org the token is
// being minted for; the caller has already resolved org → tenant.
func getRunnerToken(cfg *Config, installToken, org, kind string) (string, error) {
	var url string
	if cfg.GitHubRepo != "" {
		url = fmt.Sprintf("%s/repos/%s/%s/actions/runners/%s-token",
			cfg.githubBaseURL, org, cfg.GitHubRepo, kind)
	} else {
		url = fmt.Sprintf("%s/orgs/%s/actions/runners/%s-token",
			cfg.githubBaseURL, org, kind)
	}

	headers := map[string]string{
		"Authorization": "Bearer " + installToken,
		"Accept":        "application/vnd.github.v3+json",
		"User-Agent":    "github-app-token-server",
	}

	metricOp := "get_" + kind + "_token"

	resp, body, err := doRequestWithRetry("POST", url, headers)
	if err != nil {
		if metrics != nil {
			metrics.recordGitHubAPIError(metricOp)
		}
		return "", fmt.Errorf("requesting %s token: %w", kind, err)
	}

	if resp.StatusCode != http.StatusCreated {
		if metrics != nil {
			metrics.recordGitHubAPIError(metricOp)
		}
		// Return authError for auth-related failures so caller can retry with fresh token
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return "", &authError{statusCode: resp.StatusCode, body: string(body)}
		}
		return "", fmt.Errorf("GitHub API returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	return result.Token, nil
}

// ── HTTP Handlers ───────────────────────────────────────────────────

// runnerTokenHandler returns an HTTP handler that fetches a runner registration
// or removal token. kind is "registration" or "remove".
//
// Routing: the org is taken from the ?org= query param. If absent, falls back
// to cfg.DefaultOrg (set via GITHUB_ORG, or implicit when only one tenant is
// configured). 400 if no org can be resolved; 404 if the requested org has
// no tenant configured.
func runnerTokenHandler(cfg *Config, kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		org := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("org")))
		if org == "" {
			org = cfg.DefaultOrg
		}
		if org == "" {
			http.Error(w, "org query parameter required (no default configured)", http.StatusBadRequest)
			return
		}

		tenant, ok := cfg.Tenants[org]
		if !ok {
			http.Error(w, fmt.Sprintf("no tenant configured for org %q", org), http.StatusNotFound)
			return
		}

		installToken, err := getInstallationToken(cfg, tenant)
		if err != nil {
			slog.Error("failed to get installation token", "org", org, "error", err)
			http.Error(w, "Failed to get installation token", http.StatusInternalServerError)
			return
		}

		token, err := getRunnerToken(cfg, installToken, org, kind)
		if err != nil {
			// If the call failed due to auth error, the cached installation token
			// may have been revoked externally. Invalidate cache and retry once.
			if isAuthError(err) {
				slog.Warn("runner token request failed with auth error, retrying with fresh token",
					"org", org, "kind", kind, "error", err)
				invalidateTokenCache(org)

				installToken, err = getInstallationToken(cfg, tenant)
				if err != nil {
					slog.Error("failed to get installation token on retry", "org", org, "error", err)
					http.Error(w, "Failed to get installation token", http.StatusInternalServerError)
					return
				}

				token, err = getRunnerToken(cfg, installToken, org, kind)
				if err != nil {
					slog.Error("failed to get runner token on retry", "org", org, "kind", kind, "error", err)
					http.Error(w, "Failed to get runner token", http.StatusInternalServerError)
					return
				}
			} else {
				slog.Error("failed to get runner token", "org", org, "kind", kind, "error", err)
				http.Error(w, "Failed to get runner token", http.StatusInternalServerError)
				return
			}
		}

		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, token)
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"healthy"}`)
}

// instrumentHandler wraps an http.HandlerFunc to record metrics.
func instrumentHandler(endpoint string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next(rw, r)
		duration := time.Since(start)

		if metrics != nil {
			metrics.recordRequest(endpoint, rw.statusCode, duration)
		}

		slog.Info("request",
			"endpoint", endpoint,
			"method", r.Method,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	}
}

// responseWriter captures the status code written by the handler.
type responseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.statusCode = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

// ── Metrics Exposition ──────────────────────────────────────────────

func metricsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder

	// token_server_up
	b.WriteString("# HELP token_server_up Indicates the token server is running\n")
	b.WriteString("# TYPE token_server_up gauge\n")
	b.WriteString("token_server_up 1\n")

	if metrics == nil {
		w.Write([]byte(b.String()))
		return
	}

	metrics.mu.Lock()
	// Snapshot under lock, then release
	reqTotal := make(map[string]map[int]int64, len(metrics.httpRequestsTotal))
	for ep, codes := range metrics.httpRequestsTotal {
		c := make(map[int]int64, len(codes))
		for code, count := range codes {
			c[code] = count
		}
		reqTotal[ep] = c
	}

	durationObs := make(map[string][]float64, len(metrics.httpDurationObs))
	for ep, obs := range metrics.httpDurationObs {
		cp := make([]float64, len(obs))
		copy(cp, obs)
		durationObs[ep] = cp
	}

	apiErrors := make(map[string]int64, len(metrics.githubAPIErrors))
	for op, count := range metrics.githubAPIErrors {
		apiErrors[op] = count
	}
	metrics.mu.Unlock()

	cacheHits := metrics.cacheHits.Load()
	cacheMisses := metrics.cacheMisses.Load()

	// token_server_http_requests_total
	b.WriteString("\n# HELP token_server_http_requests_total Total HTTP requests\n")
	b.WriteString("# TYPE token_server_http_requests_total counter\n")
	for _, ep := range sortedKeys(reqTotal) {
		codes := reqTotal[ep]
		for _, code := range sortedIntKeys(codes) {
			fmt.Fprintf(&b, "token_server_http_requests_total{endpoint=%q,status=\"%d\"} %d\n",
				ep, code, codes[code])
		}
	}

	// token_server_http_request_duration_seconds (histogram)
	buckets := []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	b.WriteString("\n# HELP token_server_http_request_duration_seconds HTTP request duration\n")
	b.WriteString("# TYPE token_server_http_request_duration_seconds histogram\n")
	for _, ep := range sortedKeys(durationObs) {
		obs := durationObs[ep]
		sort.Float64s(obs)
		var sum float64
		for _, v := range obs {
			sum += v
		}
		count := len(obs)

		for _, bound := range buckets {
			n := sort.SearchFloat64s(obs, bound+1e-9) // count of obs <= bound
			fmt.Fprintf(&b, "token_server_http_request_duration_seconds_bucket{endpoint=%q,le=\"%s\"} %d\n",
				ep, formatFloat(bound), n)
		}
		fmt.Fprintf(&b, "token_server_http_request_duration_seconds_bucket{endpoint=%q,le=\"+Inf\"} %d\n", ep, count)
		fmt.Fprintf(&b, "token_server_http_request_duration_seconds_sum{endpoint=%q} %s\n", ep, formatFloat(sum))
		fmt.Fprintf(&b, "token_server_http_request_duration_seconds_count{endpoint=%q} %d\n", ep, count)
	}

	// token_server_cache_hits_total / misses
	b.WriteString("\n# HELP token_server_cache_hits_total Installation token cache hits\n")
	b.WriteString("# TYPE token_server_cache_hits_total counter\n")
	fmt.Fprintf(&b, "token_server_cache_hits_total %d\n", cacheHits)

	b.WriteString("\n# HELP token_server_cache_misses_total Installation token cache misses\n")
	b.WriteString("# TYPE token_server_cache_misses_total counter\n")
	fmt.Fprintf(&b, "token_server_cache_misses_total %d\n", cacheMisses)

	// token_server_github_api_errors_total
	b.WriteString("\n# HELP token_server_github_api_errors_total GitHub API errors\n")
	b.WriteString("# TYPE token_server_github_api_errors_total counter\n")
	for _, op := range sortedKeys(apiErrors) {
		fmt.Fprintf(&b, "token_server_github_api_errors_total{operation=%q} %d\n", op, apiErrors[op])
	}

	w.Write([]byte(b.String()))
}

// ── Helpers ─────────────────────────────────────────────────────────

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

func formatFloat(f float64) string {
	if f == math.Trunc(f) {
		return fmt.Sprintf("%.1f", f)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}
