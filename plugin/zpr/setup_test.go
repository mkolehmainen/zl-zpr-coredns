package zpr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
)

// writeTestCA writes a self-signed CA certificate PEM usable as tls_ca.
func writeTestCA(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeTestKeyFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("setup-test-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSetupMinimalConfigGetsDefaults(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)
	c := caddy.NewTestController("dns", `zpr {
		api_key_file `+keyFile+`
		tls_ca `+ca+`
	}`)
	c.ServerBlockKeys = []string{"zpr.:53"}

	z, err := parseZpr(c)
	if err != nil {
		t.Fatalf("parseZpr: %v", err)
	}
	if z.Endpoint != "https://[fd5a:5052::1]:8182" {
		t.Errorf("Endpoint = %q, want default https://[fd5a:5052::1]:8182", z.Endpoint)
	}
	if z.TTL != 30 {
		t.Errorf("TTL = %d, want 30", z.TTL)
	}
	if z.NegativeTTL != 10 {
		t.Errorf("NegativeTTL = %d, want 10", z.NegativeTTL)
	}
	if z.client == nil {
		t.Fatal("client is nil")
	}
	if z.client.Timeout != 2*time.Second {
		t.Errorf("client.Timeout = %v, want 2s", z.client.Timeout)
	}
	if z.apiKey != "setup-test-key" {
		t.Errorf("apiKey = %q, want %q (trailing newline stripped)", z.apiKey, "setup-test-key")
	}
	if len(z.Zones) != 1 || z.Zones[0] != "zpr." {
		t.Errorf("Zones = %v, want [zpr.] from the server block", z.Zones)
	}
}

func TestSetupAllOptions(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)
	c := caddy.NewTestController("dns", `zpr {
		endpoint https://[fd5a:5052::2]:9999
		api_key_file `+keyFile+`
		tls_ca `+ca+`
		tls_servername vs.zpr
		ttl 60
		negative_ttl 5
		timeout 5s
	}`)
	c.ServerBlockKeys = []string{"zpr.:53"}

	z, err := parseZpr(c)
	if err != nil {
		t.Fatalf("parseZpr: %v", err)
	}
	if z.Endpoint != "https://[fd5a:5052::2]:9999" {
		t.Errorf("Endpoint = %q", z.Endpoint)
	}
	if z.TTL != 60 || z.NegativeTTL != 5 {
		t.Errorf("TTL/NegativeTTL = %d/%d, want 60/5", z.TTL, z.NegativeTTL)
	}
	if z.client.Timeout != 5*time.Second {
		t.Errorf("client.Timeout = %v, want 5s", z.client.Timeout)
	}
}

func TestSetupMissingRequiredOptionsFail(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)

	cases := []struct {
		name string
		conf string
	}{
		{"missing api_key_file", `zpr {
			tls_ca ` + ca + `
		}`},
		{"missing tls_ca", `zpr {
			api_key_file ` + keyFile + `
		}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.conf)
			c.ServerBlockKeys = []string{"zpr.:53"}
			if _, err := parseZpr(c); err == nil {
				t.Fatal("parseZpr succeeded, want error")
			}
		})
	}
}

func TestSetupZprTwiceInBlockFails(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)
	conf := `zpr {
		api_key_file ` + keyFile + `
		tls_ca ` + ca + `
	}
	zpr {
		api_key_file ` + keyFile + `
		tls_ca ` + ca + `
	}`
	c := caddy.NewTestController("dns", conf)
	c.ServerBlockKeys = []string{"zpr.:53"}
	if _, err := parseZpr(c); err == nil {
		t.Fatal("parseZpr accepted zpr twice in one server block, want error")
	}
}

func TestSetupUnknownTokensFail(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)

	base := `
		api_key_file ` + keyFile + `
		tls_ca ` + ca

	for _, tok := range []string{
		"bogus_option x",
		"insecure_skip_verify",
		"insecure-skip-verify",
		"tls_insecure_skip_verify",
		"insecure true",
	} {
		t.Run(tok, func(t *testing.T) {
			c := caddy.NewTestController("dns", "zpr {"+base+"\n\t\t"+tok+"\n\t}")
			c.ServerBlockKeys = []string{"zpr.:53"}
			_, err := parseZpr(c)
			if err == nil {
				t.Fatalf("parseZpr accepted unknown token %q, want error", tok)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(strings.Fields(tok)[0])) {
				t.Logf("error does not name the token (acceptable): %v", err)
			}
		})
	}
}

func TestSetupBadDurationAndTTLFail(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)
	base := `
		api_key_file ` + keyFile + `
		tls_ca ` + ca

	for _, tok := range []string{"ttl potato", "negative_ttl -1", "timeout potato"} {
		t.Run(tok, func(t *testing.T) {
			c := caddy.NewTestController("dns", "zpr {"+base+"\n\t\t"+tok+"\n\t}")
			c.ServerBlockKeys = []string{"zpr.:53"}
			if _, err := parseZpr(c); err == nil {
				t.Fatalf("parseZpr accepted %q, want error", tok)
			}
		})
	}
}

func TestSetupMissingFilesFail(t *testing.T) {
	ca := writeTestCA(t)
	keyFile := writeTestKeyFile(t)

	cases := []struct {
		name string
		conf string
	}{
		{"nonexistent key file", `zpr {
			api_key_file /nonexistent/key
			tls_ca ` + ca + `
		}`},
		{"nonexistent CA file", `zpr {
			api_key_file ` + keyFile + `
			tls_ca /nonexistent/ca.pem
		}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.conf)
			c.ServerBlockKeys = []string{"zpr.:53"}
			if _, err := parseZpr(c); err == nil {
				t.Fatal("parseZpr succeeded, want error")
			}
		})
	}
}
