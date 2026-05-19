package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

// ── Test Helpers ────────────────────────────────────────────────────

// Shared test key to avoid expensive RSA generation under -race.
var (
	sharedTestKey     *rsa.PrivateKey
	sharedTestKeyOnce sync.Once
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	sharedTestKeyOnce.Do(func() {
		var err error
		sharedTestKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("generating test RSA key: %v", err))
		}
	})
	return sharedTestKey
}

// generateDistinctTestKey returns a fresh RSA key — used by tests that need
// to verify per-tenant key isolation. Slow under -race, so reserve for the
// one or two tests that actually exercise distinct keys.
func generateDistinctTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating distinct test key: %v", err)
	}
	return key
}

func encodePKCS1PEM(key *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
}

func encodePKCS8PEM(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
}

// writeTempKeyFile writes a PKCS1-PEM-encoded key to a temp file and returns
// its path. Used by GITHUB_APP_TENANTS tests that need real key files.
func writeTempKeyFile(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-key.pem")
	if err := os.WriteFile(path, []byte(encodePKCS1PEM(key)), 0o600); err != nil {
		t.Fatalf("writing temp key file: %v", err)
	}
	return path
}

// testConfig returns a Config with one tenant ("test-org" → app 12345, install
// 67890), matching the legacy single-tenant test setup. The shared test key
// is reused — distinct-key tests build their own Config.
func testConfig(t *testing.T, baseURL string) *Config {
	t.Helper()
	key := generateTestKey(t)
	return &Config{
		Tenants: map[string]*Tenant{
			"test-org": {
				Org:            "test-org",
				AppID:          "12345",
				InstallationID: 67890,
				PrivateKey:     key,
			},
		},
		DefaultOrg:    "test-org",
		ListenAddr:    ":0",
		githubBaseURL: baseURL,
	}
}

// testTenant returns the canonical single tenant used by tests that exercise
// the per-tenant getInstallationToken signature.
func testTenant(t *testing.T) *Tenant {
	t.Helper()
	return &Tenant{
		Org:            "test-org",
		AppID:          "12345",
		InstallationID: 67890,
		PrivateKey:     generateTestKey(t),
	}
}

// resetCache clears the global cache between tests.
func resetCache() {
	cache.mu.Lock()
	cache.entries = map[string]tokenCacheEntry{}
	cache.mu.Unlock()
}

// clearTokenEnv unsets every env var loadConfig consults. Tests call this
// before t.Setenv-ing the inputs they want to exercise so leakage from a
// prior subtest can't masquerade as a passing case.
func clearTokenEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GITHUB_APP_TENANTS",
		"GITHUB_APP_ID",
		"GITHUB_APP_INSTALLATION_ID",
		"GITHUB_APP_INSTALLATIONS",
		"GITHUB_APP_PRIVATE_KEY",
		"GITHUB_APP_PRIVATE_KEY_PATH",
		"GITHUB_ORG",
		"GITHUB_REPO",
		"TOKEN_SERVER_ADDR",
	} {
		t.Setenv(k, "")
	}
}

// ── TestLoadConfig (legacy single-App path) ─────────────────────────

func TestLoadConfig(t *testing.T) {
	key := generateTestKey(t)
	keyPEM := encodePKCS1PEM(key)

	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "missing all config",
			env:     map[string]string{},
			wantErr: "set GITHUB_APP_TENANTS",
		},
		{
			name: "legacy: missing both installation env vars",
			env: map[string]string{
				"GITHUB_APP_ID":          "123",
				"GITHUB_APP_PRIVATE_KEY": keyPEM,
			},
			wantErr: "set GITHUB_APP_INSTALLATIONS",
		},
		{
			name: "legacy: non-numeric GITHUB_APP_INSTALLATION_ID",
			env: map[string]string{
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_PRIVATE_KEY":     keyPEM,
				"GITHUB_APP_INSTALLATION_ID": "xyz",
				"GITHUB_ORG":                 "my-org",
			},
			wantErr: "GITHUB_APP_INSTALLATION_ID must be a number",
		},
		{
			name: "legacy: missing private key",
			env: map[string]string{
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_INSTALLATION_ID": "456",
				"GITHUB_ORG":                 "my-org",
			},
			wantErr: "failed to load private key",
		},
		{
			name: "legacy multi-org: malformed entry",
			env: map[string]string{
				"GITHUB_APP_ID":            "123",
				"GITHUB_APP_INSTALLATIONS": "no-colon-here",
				"GITHUB_APP_PRIVATE_KEY":   keyPEM,
			},
			wantErr: "must be org:id",
		},
		{
			name: "legacy multi-org: non-numeric id",
			env: map[string]string{
				"GITHUB_APP_ID":            "123",
				"GITHUB_APP_INSTALLATIONS": "foo:abc",
				"GITHUB_APP_PRIVATE_KEY":   keyPEM,
			},
			wantErr: "is not a number",
		},
		{
			name: "legacy multi-org: GITHUB_ORG must be in installations",
			env: map[string]string{
				"GITHUB_APP_ID":            "123",
				"GITHUB_APP_INSTALLATIONS": "foo:111,bar:222",
				"GITHUB_APP_PRIVATE_KEY":   keyPEM,
				"GITHUB_ORG":               "baz",
			},
			wantErr: "is not in configured tenants",
		},
		{
			name: "legacy: valid single-org config",
			env: map[string]string{
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_INSTALLATION_ID": "456",
				"GITHUB_APP_PRIVATE_KEY":     keyPEM,
				"GITHUB_ORG":                 "my-org",
			},
		},
		{
			name: "legacy: with custom addr",
			env: map[string]string{
				"GITHUB_APP_ID":              "123",
				"GITHUB_APP_INSTALLATION_ID": "456",
				"GITHUB_APP_PRIVATE_KEY":     keyPEM,
				"GITHUB_ORG":                 "my-org",
				"TOKEN_SERVER_ADDR":          ":9090",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearTokenEnv(t)

			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cfg, err := loadConfig()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			tenant := cfg.Tenants["my-org"]
			if tenant == nil {
				t.Fatalf("missing tenant for my-org: %+v", cfg.Tenants)
			}
			if tenant.AppID != "123" {
				t.Errorf("AppID = %q, want %q", tenant.AppID, "123")
			}
			if tenant.InstallationID != 456 {
				t.Errorf("InstallationID = %d, want 456", tenant.InstallationID)
			}
			if cfg.DefaultOrg != "my-org" {
				t.Errorf("DefaultOrg = %q, want %q", cfg.DefaultOrg, "my-org")
			}
			if cfg.githubBaseURL != "https://api.github.com" {
				t.Errorf("githubBaseURL = %q, want %q", cfg.githubBaseURL, "https://api.github.com")
			}

			if addr, ok := tt.env["TOKEN_SERVER_ADDR"]; ok && addr != "" {
				if cfg.ListenAddr != addr {
					t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, addr)
				}
			} else {
				if cfg.ListenAddr != ":8080" {
					t.Errorf("ListenAddr = %q, want default :8080", cfg.ListenAddr)
				}
			}
		})
	}
}

// ── TestLoadConfigTenants (Option B: GITHUB_APP_TENANTS) ────────────

func TestLoadConfigTenants(t *testing.T) {
	keyA := generateTestKey(t)
	keyB := generateDistinctTestKey(t)
	pathA := writeTempKeyFile(t, keyA)
	pathB := writeTempKeyFile(t, keyB)

	t.Run("two tenants with distinct App IDs and key paths", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf(
			"orgone:111111:1001:%s,orgtwo:222222:2002:%s",
			pathA, pathB,
		))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got := len(cfg.Tenants); got != 2 {
			t.Fatalf("Tenants len = %d, want 2", got)
		}

		orgone := cfg.Tenants["orgone"]
		if orgone == nil || orgone.AppID != "111111" || orgone.InstallationID != 1001 {
			t.Errorf("orgone tenant: %+v, want AppID=\"111111\" InstallationID=1001", orgone)
		}
		hordia := cfg.Tenants["orgtwo"]
		if hordia == nil || hordia.AppID != "222222" || hordia.InstallationID != 2002 {
			t.Errorf("orgtwo tenant: %+v, want AppID=\"222222\" InstallationID=2002", hordia)
		}

		// Per-tenant keys must be distinct objects — proves we loaded both files.
		if orgone.PrivateKey == hordia.PrivateKey {
			t.Error("tenants share the same key pointer; expected distinct keys")
		}
		if orgone.PrivateKey.N.Cmp(hordia.PrivateKey.N) == 0 {
			t.Error("tenant keys have identical modulus; expected distinct keys")
		}

		// With multiple tenants and no GITHUB_ORG, DefaultOrg stays empty —
		// callers must supply ?org=.
		if cfg.DefaultOrg != "" {
			t.Errorf("DefaultOrg = %q, want empty for multi-tenant", cfg.DefaultOrg)
		}
	})

	t.Run("single tenant becomes implicit default", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:111111:1001:%s", pathA))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DefaultOrg != "orgone" {
			t.Errorf("DefaultOrg = %q, want %q (single-tenant implicit default)", cfg.DefaultOrg, "orgone")
		}
	})

	t.Run("explicit GITHUB_ORG must exist in tenants", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:111111:1001:%s", pathA))
		t.Setenv("GITHUB_ORG", "nonexistent")

		_, err := loadConfig()
		if err == nil {
			t.Fatal("expected error for GITHUB_ORG not in tenants")
		}
		if !strings.Contains(err.Error(), "is not in configured tenants") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("GITHUB_APP_TENANTS wins over legacy vars", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:111111:1001:%s", pathA))
		// Legacy vars set but should be ignored when TENANTS is present.
		t.Setenv("GITHUB_APP_ID", "999999")
		t.Setenv("GITHUB_APP_INSTALLATIONS", "should-be-ignored:55555")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", encodePKCS1PEM(keyB))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := cfg.Tenants["should-be-ignored"]; ok {
			t.Error("legacy GITHUB_APP_INSTALLATIONS bled into Tenants; TENANTS should have won outright")
		}
		if cfg.Tenants["orgone"].AppID != "111111" {
			t.Errorf("AppID = %q, want %q (from TENANTS, not legacy GITHUB_APP_ID)", cfg.Tenants["orgone"].AppID, "111111")
		}
	})

	t.Run("error: malformed entry", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", "orgone:only-three:fields")
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "must be org:app_id:installation_id:key_path") {
			t.Errorf("expected schema error, got %v", err)
		}
	})

	t.Run("error: empty app_id", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone::1001:%s", pathA))
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "app_id is empty") {
			t.Errorf("expected empty app_id error, got %v", err)
		}
	})

	t.Run("string Client ID is accepted", func(t *testing.T) {
		// Newer GitHub Apps only expose a string Client ID (e.g.
		// "Iv23liqTIFEtdIu6Vn1r") — no numeric App ID. AppID is a
		// string field precisely to support that case; this test pins
		// the behavior so a future "validate as integer" refactor
		// can't silently regress it.
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:Iv23liqTIFEtdIu6Vn1r:1001:%s", pathA))
		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("string Client ID should be accepted, got %v", err)
		}
		if got := cfg.Tenants["orgone"].AppID; got != "Iv23liqTIFEtdIu6Vn1r" {
			t.Errorf("AppID = %q, want %q", got, "Iv23liqTIFEtdIu6Vn1r")
		}
	})

	t.Run("error: non-numeric installation_id", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:111111:not-a-number:%s", pathA))
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "installation_id") {
			t.Errorf("expected installation_id error, got %v", err)
		}
	})

	t.Run("error: missing key file", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", "orgone:111111:1001:/tmp/nonexistent-key-12345.pem")
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "reading key file") {
			t.Errorf("expected key file error, got %v", err)
		}
	})

	t.Run("error: duplicate org", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf(
			"orgone:111111:1001:%s,orgone:222222:2002:%s",
			pathA, pathB,
		))
		_, err := loadConfig()
		if err == nil || !strings.Contains(err.Error(), "duplicate org") {
			t.Errorf("expected duplicate-org error, got %v", err)
		}
	})

	t.Run("case-insensitive org names", func(t *testing.T) {
		clearTokenEnv(t)
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("ORGONE:111111:1001:%s", pathA))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, ok := cfg.Tenants["orgone"]; !ok {
			t.Error("tenant key should be lowercased")
		}
	})

	t.Run("key_path containing a colon parses correctly", func(t *testing.T) {
		// SplitN(entry, ":", 4) means anything after the third colon —
		// including additional colons — lands in the key_path field.
		// Without that limit, a colon-containing path (e.g. a Windows
		// path or a contrived POSIX path) would split into 5+ parts
		// and fail the "must be org:app_id:installation_id:key_path"
		// validation despite being well-formed.
		clearTokenEnv(t)
		key := generateTestKey(t)
		dir := t.TempDir()
		weirdPath := filepath.Join(dir, "ke:y.pem") // colon inside the filename
		if err := os.WriteFile(weirdPath, []byte(encodePKCS1PEM(key)), 0o600); err != nil {
			t.Fatalf("writing colon-named key file: %v", err)
		}
		t.Setenv("GITHUB_APP_TENANTS", fmt.Sprintf("orgone:111111:1001:%s", weirdPath))

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("colon in key_path should parse, got %v", err)
		}
		if _, ok := cfg.Tenants["orgone"]; !ok {
			t.Errorf("tenant should be registered when key_path contains a colon")
		}
	})
}

// ── TestLoadPrivateKey ──────────────────────────────────────────────

func TestLoadPrivateKey(t *testing.T) {
	key := generateTestKey(t)

	t.Run("PKCS1 PEM from env", func(t *testing.T) {
		t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", encodePKCS1PEM(key))

		got, err := loadPrivateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.N.Cmp(key.N) != 0 {
			t.Error("loaded key does not match original")
		}
	})

	t.Run("PKCS8 PEM from env", func(t *testing.T) {
		t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", encodePKCS8PEM(key))

		got, err := loadPrivateKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.N.Cmp(key.N) != 0 {
			t.Error("loaded key does not match original")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", "not-a-pem")

		_, err := loadPrivateKey()
		if err == nil {
			t.Fatal("expected error for invalid PEM")
		}
		if !strings.Contains(err.Error(), "failed to parse PEM block") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("missing key", func(t *testing.T) {
		t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", "")

		_, err := loadPrivateKey()
		if err == nil {
			t.Fatal("expected error for missing key")
		}
		if !strings.Contains(err.Error(), "GITHUB_APP_PRIVATE_KEY_PATH or GITHUB_APP_PRIVATE_KEY is required") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("file path with non-existent file", func(t *testing.T) {
		t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", "/tmp/nonexistent-key-12345.pem")
		t.Setenv("GITHUB_APP_PRIVATE_KEY", "")

		_, err := loadPrivateKey()
		if err == nil {
			t.Fatal("expected error for missing key file")
		}
		if !strings.Contains(err.Error(), "reading key file") {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

// ── TestGenerateJWT ─────────────────────────────────────────────────

func TestGenerateJWT(t *testing.T) {
	tenant := testTenant(t)
	key := tenant.PrivateKey

	signed, err := generateJWT(tenant)
	if err != nil {
		t.Fatalf("generateJWT failed: %v", err)
	}

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}

	if claims.Issuer != "12345" {
		t.Errorf("Issuer = %q, want %q (tenant AppID as string)", claims.Issuer, "12345")
	}

	now := time.Now()
	iat := claims.IssuedAt.Time
	if now.Sub(iat) > 90*time.Second || now.Sub(iat) < 30*time.Second {
		t.Errorf("IssuedAt %v is not ~60s before now %v", iat, now)
	}

	exp := claims.ExpiresAt.Time
	if exp.Sub(now) > 11*time.Minute || exp.Sub(now) < 9*time.Minute {
		t.Errorf("ExpiresAt %v is not ~10min after now %v", exp, now)
	}
}

// TestGenerateJWTStringClientID is the closing-loop coverage for the
// AppID-as-string change in c8c9636 (PR #78). The sibling TestGenerateJWT
// covers a stringified numeric AppID ("12345"), which doesn't actually
// exercise the new contract — a regression that called
// strconv.ParseInt(tenant.AppID, 10, 64) or otherwise required a
// numeric value would still pass that test. This test pins the
// behaviour for the non-numeric Client ID form that motivated the
// change in the first place: AppID = "Iv23liqTIFEtdIu6Vn1r" must flow
// through generateJWT verbatim into the JWT iss claim.
func TestGenerateJWTStringClientID(t *testing.T) {
	const clientID = "Iv23liqTIFEtdIu6Vn1r"
	tenant := testTenant(t)
	tenant.AppID = clientID
	key := tenant.PrivateKey

	signed, err := generateJWT(tenant)
	if err != nil {
		t.Fatalf("generateJWT failed for string Client ID: %v", err)
	}

	token, err := jwt.ParseWithClaims(signed, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("unexpected claims type")
	}

	if claims.Issuer != clientID {
		t.Errorf("Issuer = %q, want %q (string Client ID passed through verbatim)", claims.Issuer, clientID)
	}
}

// TestLoadConfigLegacyStringClientID covers the parallel case in
// parseLegacyTenants: GITHUB_APP_ID can hold a string Client ID, not
// just a numeric App ID. The table-driven TestLoadConfig exercises
// the legacy path with numeric values; this test pins the string
// form for the same path. parseTenantsCSV is already covered by
// TestLoadConfigTenants/"string Client ID is accepted".
func TestLoadConfigLegacyStringClientID(t *testing.T) {
	const clientID = "Iv23liqTIFEtdIu6Vn1r"
	key := generateTestKey(t)
	keyPEM := encodePKCS1PEM(key)

	clearTokenEnv(t)
	t.Setenv("GITHUB_APP_ID", clientID)
	t.Setenv("GITHUB_APP_INSTALLATION_ID", "456")
	t.Setenv("GITHUB_APP_PRIVATE_KEY", keyPEM)
	t.Setenv("GITHUB_ORG", "my-org")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("legacy GITHUB_APP_ID with string Client ID should be accepted, got %v", err)
	}

	tenant := cfg.Tenants["my-org"]
	if tenant == nil {
		t.Fatalf("missing tenant for my-org: %+v", cfg.Tenants)
	}
	if tenant.AppID != clientID {
		t.Errorf("AppID = %q, want %q (string Client ID stored verbatim)", tenant.AppID, clientID)
	}
}

// ── TestGetInstallationToken ────────────────────────────────────────

func TestGetInstallationToken(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	t.Run("success", func(t *testing.T) {
		resetCache()
		expiresAt := time.Now().Add(1 * time.Hour)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/app/installations/67890/access_tokens" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Method != "POST" {
				t.Errorf("unexpected method: %s", r.Method)
			}
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				t.Error("missing Bearer token")
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_test_installation_token",
				"expires_at": expiresAt.Format(time.RFC3339),
			})
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		token, err := getInstallationToken(cfg, cfg.Tenants["test-org"])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "ghs_test_installation_token" {
			t.Errorf("token = %q, want %q", token, "ghs_test_installation_token")
		}
	})

	t.Run("cache hit", func(t *testing.T) {
		resetCache()
		var callCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount.Add(1)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_cached",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		tenant := cfg.Tenants["test-org"]

		// First call → cache miss
		token1, err := getInstallationToken(cfg, tenant)
		if err != nil {
			t.Fatalf("first call: %v", err)
		}

		// Second call → cache hit
		token2, err := getInstallationToken(cfg, tenant)
		if err != nil {
			t.Fatalf("second call: %v", err)
		}

		if token1 != token2 {
			t.Errorf("tokens differ: %q vs %q", token1, token2)
		}
		if callCount.Load() != 1 {
			t.Errorf("API called %d times, want 1 (second should be cached)", callCount.Load())
		}
	})

	t.Run("401 error", func(t *testing.T) {
		resetCache()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"Bad credentials"}`)
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		_, err := getInstallationToken(cfg, cfg.Tenants["test-org"])
		if err == nil {
			t.Fatal("expected error for 401")
		}
		if !strings.Contains(err.Error(), "401") {
			t.Errorf("error should mention 401: %v", err)
		}
	})

	t.Run("500 then 201 retry", func(t *testing.T) {
		resetCache()
		var callCount atomic.Int32

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := callCount.Add(1)
			if n == 1 {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, "internal error")
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_after_retry",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		token, err := getInstallationToken(cfg, cfg.Tenants["test-org"])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "ghs_after_retry" {
			t.Errorf("token = %q, want %q", token, "ghs_after_retry")
		}
		if callCount.Load() != 2 {
			t.Errorf("API called %d times, want 2 (retry after 500)", callCount.Load())
		}
	})
}

// ── TestGetRegistrationToken ────────────────────────────────────────

func TestGetRegistrationToken(t *testing.T) {
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	t.Run("org-level URL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := "/orgs/test-org/actions/runners/registration-token"
			if r.URL.Path != expected {
				t.Errorf("path = %q, want %q", r.URL.Path, expected)
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ABRTU_org_token",
				"expires_at": "2025-01-01T00:00:00Z",
			})
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		cfg.GitHubRepo = "" // org-level

		token, err := getRunnerToken(cfg, "install-token", "test-org", "registration")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "ABRTU_org_token" {
			t.Errorf("token = %q, want %q", token, "ABRTU_org_token")
		}
	})

	t.Run("repo-level URL", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			expected := "/repos/test-org/my-repo/actions/runners/registration-token"
			if r.URL.Path != expected {
				t.Errorf("path = %q, want %q", r.URL.Path, expected)
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ABRTU_repo_token",
				"expires_at": "2025-01-01T00:00:00Z",
			})
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		cfg.GitHubRepo = "my-repo"

		token, err := getRunnerToken(cfg, "install-token", "test-org", "registration")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "ABRTU_repo_token" {
			t.Errorf("token = %q, want %q", token, "ABRTU_repo_token")
		}
	})

	t.Run("error response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"Resource not accessible by integration"}`)
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		_, err := getRunnerToken(cfg, "install-token", "test-org", "registration")
		if err == nil {
			t.Fatal("expected error")
		}
		if !strings.Contains(err.Error(), "403") {
			t.Errorf("error should mention 403: %v", err)
		}
	})
}

// ── TestTokenHandler ────────────────────────────────────────────────

func TestTokenHandler(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	t.Run("success", func(t *testing.T) {
		resetCache()

		// Mock both API calls: installation token then registration token
		var reqCount atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			n := reqCount.Add(1)
			if n <= 1 && strings.Contains(r.URL.Path, "/app/installations/") {
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token":      "ghs_install",
					"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				})
				return
			}
			if strings.Contains(r.URL.Path, "/actions/runners/registration-token") {
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token":      "ABRTU_reg_token",
					"expires_at": "2025-01-01T00:00:00Z",
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		handler := runnerTokenHandler(cfg, "registration")

		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if rec.Body.String() != "ABRTU_reg_token" {
			t.Errorf("body = %q, want %q", rec.Body.String(), "ABRTU_reg_token")
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		cfg := testConfig(t, "http://unused")
		handler := runnerTokenHandler(cfg, "registration")

		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusMethodNotAllowed)
		}
	})

	t.Run("installation token failure", func(t *testing.T) {
		resetCache()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"Bad credentials"}`)
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		handler := runnerTokenHandler(cfg, "registration")

		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
	})

	t.Run("remove-token success hits remove URL", func(t *testing.T) {
		resetCache()

		var sawRemovePath atomic.Bool
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/app/installations/") {
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token":      "ghs_install",
					"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
				})
				return
			}
			if strings.HasSuffix(r.URL.Path, "/actions/runners/remove-token") {
				sawRemovePath.Store(true)
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"token":      "ABRTU_remove_token",
					"expires_at": "2025-01-01T00:00:00Z",
				})
				return
			}
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		cfg := testConfig(t, server.URL)
		handler := runnerTokenHandler(cfg, "remove")

		req := httptest.NewRequest(http.MethodGet, "/remove-token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if rec.Body.String() != "ABRTU_remove_token" {
			t.Errorf("body = %q, want %q", rec.Body.String(), "ABRTU_remove_token")
		}
		if !sawRemovePath.Load() {
			t.Error("expected request to /actions/runners/remove-token, none observed")
		}
	})
}

// ── TestMultiTenantRouting ──────────────────────────────────────────

// Each tenant must use ITS OWN AppID + private key to sign the JWT and ITS
// OWN installation ID to fetch tokens — that's the core promise of Option B.
func TestMultiTenantRouting(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	// Three tenants with distinct AppIDs and installation IDs. Keys are
	// shared (faster under -race); the dedicated TestPerTenantKeyIsolation
	// below proves we sign with the right key.
	sharedKey := generateTestKey(t)
	tenants := map[string]*Tenant{
		"orgone":   {Org: "orgone", AppID: "111111", InstallationID: 1001, PrivateKey: sharedKey},
		"orgtwo":   {Org: "orgtwo", AppID: "222222", InstallationID: 2002, PrivateKey: sharedKey},
		"otherorg": {Org: "otherorg", AppID: "333333", InstallationID: 3003, PrivateKey: sharedKey},
	}

	// Mock GitHub API — capture which installation was hit, which JWT issuer
	// was used (== signing AppID), and which org URL was used.
	var lastInstallationID atomic.Int64
	var lastJWTIssuer atomic.Value // string
	var lastOrgInPath atomic.Value // string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, _ := extractInstallationID(r.URL.Path); id != 0 {
			lastInstallationID.Store(id)

			// Pull the JWT issuer out of the Authorization header — proves
			// the per-tenant AppID was used to sign.
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(auth, "Bearer ") {
				tokenStr := strings.TrimPrefix(auth, "Bearer ")
				parser := jwt.NewParser()
				tok, _, _ := parser.ParseUnverified(tokenStr, &jwt.RegisteredClaims{})
				if claims, ok := tok.Claims.(*jwt.RegisteredClaims); ok {
					lastJWTIssuer.Store(claims.Issuer)
				}
			}

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      fmt.Sprintf("ghs_install_%d", id),
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
			return
		}
		if org := extractOrgFromRunnerPath(r.URL.Path); org != "" {
			lastOrgInPath.Store(org)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "ABRTU_" + org,
				"expires_at": "2026-12-31T00:00:00Z",
			})
			return
		}
		t.Errorf("unexpected request to %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		Tenants: tenants,
		// DefaultOrg deliberately empty — caller must specify ?org=
		ListenAddr:    ":0",
		githubBaseURL: server.URL,
	}
	handler := runnerTokenHandler(cfg, "registration")

	t.Run("routes to correct installation, AppID, and org per tenant", func(t *testing.T) {
		for org, tenant := range tenants {
			resetCache()
			req := httptest.NewRequest(http.MethodGet, "/token?org="+org, nil)
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("org %q: status = %d, want 200, body=%s", org, rec.Code, rec.Body.String())
				continue
			}
			if got := lastInstallationID.Load(); got != tenant.InstallationID {
				t.Errorf("org %q: installation id = %d, want %d", org, got, tenant.InstallationID)
			}
			if got, _ := lastJWTIssuer.Load().(string); got != tenant.AppID {
				t.Errorf("org %q: JWT issuer = %q, want %q (per-tenant AppID)", org, got, tenant.AppID)
			}
			if got, _ := lastOrgInPath.Load().(string); got != org {
				t.Errorf("org %q: org in URL path = %q, want %q", org, got, org)
			}
		}
	})

	t.Run("400 when no org provided and no default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
		}
	})

	t.Run("404 for unknown tenant", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/token?org=nonexistent", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d, body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
		}
	})

	t.Run("org param is case-insensitive", func(t *testing.T) {
		resetCache()
		req := httptest.NewRequest(http.MethodGet, "/token?org=ORGONE", nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200, body=%s", rec.Code, rec.Body.String())
		}
		if got := lastInstallationID.Load(); got != 1001 {
			t.Errorf("installation id = %d, want 1001 (orgone)", got)
		}
	})
}

// ── TestPerTenantKeyIsolation ───────────────────────────────────────

// Proves the JWT for each tenant was signed with that tenant's private key,
// not a sibling's. Uses one distinct key per tenant (slower than sharing,
// but the whole point of this test).
func TestPerTenantKeyIsolation(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	keyA := generateDistinctTestKey(t)
	keyB := generateDistinctTestKey(t)

	tenants := map[string]*Tenant{
		"orga": {Org: "orga", AppID: "111", InstallationID: 1001, PrivateKey: keyA},
		"orgb": {Org: "orgb", AppID: "222", InstallationID: 2002, PrivateKey: keyB},
	}

	// Captures the raw JWT presented for each installation. We then verify
	// signature using the public key we *expect* to have signed it — wrong
	// key → invalid signature → test fails.
	jwtByInstallation := sync.Map{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, _ := extractInstallationID(r.URL.Path); id != 0 {
			auth := r.Header.Get("Authorization")
			tokenStr := strings.TrimPrefix(auth, "Bearer ")
			jwtByInstallation.Store(id, tokenStr)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "ghs_install",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
			return
		}
		if extractOrgFromRunnerPath(r.URL.Path) != "" {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{
				"token":      "ABRTU_test",
				"expires_at": "2026-12-31T00:00:00Z",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := &Config{
		Tenants:       tenants,
		ListenAddr:    ":0",
		githubBaseURL: server.URL,
	}
	handler := runnerTokenHandler(cfg, "registration")

	for org, tenant := range tenants {
		resetCache()
		req := httptest.NewRequest(http.MethodGet, "/token?org="+org, nil)
		rec := httptest.NewRecorder()
		handler(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("org %q: status = %d, want 200, body=%s", org, rec.Code, rec.Body.String())
		}

		raw, ok := jwtByInstallation.Load(tenant.InstallationID)
		if !ok {
			t.Fatalf("org %q: no JWT captured for installation %d", org, tenant.InstallationID)
		}

		// Verify with the tenant's expected public key. Wrong key would fail
		// here, proving per-tenant signing isolation.
		_, err := jwt.Parse(raw.(string), func(token *jwt.Token) (any, error) {
			return &tenant.PrivateKey.PublicKey, nil
		})
		if err != nil {
			t.Errorf("org %q: JWT did NOT verify with tenant's own key: %v", org, err)
		}

		// Cross-check: it should fail to verify with the OTHER tenant's key.
		var otherKey *rsa.PrivateKey
		for otherOrg, otherTenant := range tenants {
			if otherOrg != org {
				otherKey = otherTenant.PrivateKey
				break
			}
		}
		_, err = jwt.Parse(raw.(string), func(token *jwt.Token) (any, error) {
			return &otherKey.PublicKey, nil
		})
		if err == nil {
			t.Errorf("org %q: JWT verified with WRONG key — per-tenant isolation broken", org)
		}
	}
}

// extractInstallationID returns the numeric ID from
// /app/installations/{id}/access_tokens, or 0 if the path doesn't match.
func extractInstallationID(path string) (int64, bool) {
	const prefix = "/app/installations/"
	const suffix = "/access_tokens"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return 0, false
	}
	mid := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	id, err := strconv.ParseInt(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return id, true
}

// extractOrgFromRunnerPath returns the org name from
// /orgs/{org}/actions/runners/{registration|remove}-token, or "" otherwise.
func extractOrgFromRunnerPath(path string) string {
	if !strings.HasPrefix(path, "/orgs/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/orgs/")
	slash := strings.Index(rest, "/")
	if slash < 0 {
		return ""
	}
	return rest[:slash]
}

// ── TestHealthHandler ───────────────────────────────────────────────

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body["status"] != "healthy" {
		t.Errorf("status = %q, want %q", body["status"], "healthy")
	}
}

// ── TestMetricsHandler ──────────────────────────────────────────────

func TestMetricsHandler(t *testing.T) {
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	// Record some data to exercise all metric paths
	metrics.recordRequest("/token", 200, 50*time.Millisecond)
	metrics.recordRequest("/health", 200, 1*time.Millisecond)
	metrics.cacheHits.Add(5)
	metrics.cacheMisses.Add(2)
	metrics.recordGitHubAPIError("get_installation_token")

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	metricsHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", ct)
	}

	body := rec.Body.String()

	expectedMetrics := []string{
		"token_server_up 1",
		"token_server_http_requests_total",
		"token_server_http_request_duration_seconds_bucket",
		"token_server_http_request_duration_seconds_sum",
		"token_server_http_request_duration_seconds_count",
		"token_server_cache_hits_total 5",
		"token_server_cache_misses_total 2",
		"token_server_github_api_errors_total",
	}

	for _, m := range expectedMetrics {
		if !strings.Contains(body, m) {
			t.Errorf("metrics output missing %q", m)
		}
	}

	// Validate TYPE lines exist
	for _, typeLine := range []string{
		"# TYPE token_server_up gauge",
		"# TYPE token_server_http_requests_total counter",
		"# TYPE token_server_http_request_duration_seconds histogram",
		"# TYPE token_server_cache_hits_total counter",
		"# TYPE token_server_cache_misses_total counter",
		"# TYPE token_server_github_api_errors_total counter",
	} {
		if !strings.Contains(body, typeLine) {
			t.Errorf("metrics output missing TYPE line: %q", typeLine)
		}
	}

	// Check +Inf bucket exists
	if !strings.Contains(body, `le="+Inf"`) {
		t.Error("metrics output missing +Inf bucket")
	}
}

// ── TestCacheThunderingHerd ─────────────────────────────────────────

func TestCacheThunderingHerd(t *testing.T) {
	resetCache()
	metrics = newServerMetrics()
	defer func() { metrics = nil }()

	var apiCalls atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/app/installations/") {
			apiCalls.Add(1)
			// Simulate slow API
			time.Sleep(50 * time.Millisecond)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_herd_test",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := testConfig(t, server.URL)
	tenant := cfg.Tenants["test-org"]

	const numCallers = 10
	var wg sync.WaitGroup
	wg.Add(numCallers)

	tokens := make([]string, numCallers)
	errs := make([]error, numCallers)

	for i := 0; i < numCallers; i++ {
		go func(idx int) {
			defer wg.Done()
			tokens[idx], errs[idx] = getInstallationToken(cfg, tenant)
		}(i)
	}

	wg.Wait()

	for i := 0; i < numCallers; i++ {
		if errs[i] != nil {
			t.Errorf("caller %d got error: %v", i, errs[i])
		}
		if tokens[i] != "ghs_herd_test" {
			t.Errorf("caller %d got token %q, want %q", i, tokens[i], "ghs_herd_test")
		}
	}

	// The thundering herd fix means only 1 API call should have been made
	calls := apiCalls.Load()
	if calls != 1 {
		t.Errorf("API called %d times, want exactly 1 (thundering herd not prevented)", calls)
	}
}
