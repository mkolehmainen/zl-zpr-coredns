package zpr

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() { plugin.Register("zpr", setup) }

func setup(c *caddy.Controller) error {
	z, err := parseZpr(c)
	if err != nil {
		return plugin.Error("zpr", err)
	}
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		z.Next = next
		return z
	})
	return nil
}

// parseZpr parses the Corefile stanza per README.md, "Corefile syntax".
// The API key file is read once here, at setup; the zone comes from the server block.
func parseZpr(c *caddy.Controller) (*Zpr, error) {
	z := &Zpr{
		Endpoint:    "https://[fd5a:5052::1]:8182",
		TTL:         30,
		NegativeTTL: 10,
	}
	timeout := 2 * time.Second
	var keyFile, caFile, serverName string

	seen := false
	for c.Next() {
		if seen {
			return nil, c.Err("zpr may appear at most once per server block")
		}
		seen = true
		if len(c.RemainingArgs()) > 0 {
			return nil, c.ArgErr()
		}
		for c.NextBlock() {
			switch c.Val() {
			case "endpoint":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				if err := validateEndpoint(c.Val()); err != nil {
					return nil, c.Errf("endpoint %q: %v", c.Val(), err)
				}
				z.Endpoint = c.Val()
			case "api_key_file":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				keyFile = c.Val()
			case "tls_ca":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				caFile = c.Val()
			case "tls_servername":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				serverName = c.Val()
			case "ttl":
				n, err := parseTTLArg(c)
				if err != nil {
					return nil, err
				}
				z.TTL = n
			case "negative_ttl":
				n, err := parseTTLArg(c)
				if err != nil {
					return nil, err
				}
				z.NegativeTTL = n
			case "timeout":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil || d <= 0 {
					return nil, c.Errf("invalid timeout %q: %v", c.Val(), err)
				}
				timeout = d
			default:
				// Unknown tokens are errors. In particular, no
				// insecure-skip-verify option exists, deliberately: the
				// admin API cert is always verified against tls_ca.
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if keyFile == "" {
		return nil, c.Err("api_key_file is required")
	}
	if caFile == "" {
		return nil, c.Err("tls_ca is required")
	}

	key, err := readAPIKey(keyFile)
	if err != nil {
		return nil, fmt.Errorf("reading api_key_file: %w", err)
	}
	z.apiKey = key

	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("reading tls_ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("tls_ca %s contains no usable PEM certificates", caFile)
	}

	z.client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
				ServerName: serverName,
			},
		},
	}

	// The zone comes from the server block, not the plugin stanza.
	z.Zones = plugin.OriginsFromArgsOrServerBlock(nil, c.ServerBlockKeys)

	return z, nil
}

func parseTTLArg(c *caddy.Controller) (uint32, error) {
	if !c.NextArg() {
		return 0, c.ArgErr()
	}
	n, err := strconv.ParseUint(c.Val(), 10, 32)
	if err != nil {
		return 0, c.Errf("invalid TTL %q: %v", c.Val(), err)
	}
	return uint32(n), nil
}

// validateEndpoint requires an https URL with a host. Anything else — in
// particular http — would send the X-API-Key credential in plaintext and
// bypass the tls_ca verification this plugin guarantees, so it is rejected
// at setup rather than discovered at query time.
func validateEndpoint(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL (the admin API endpoint must be an https URL): %v", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("scheme %q is not allowed: the admin API endpoint must use https, so the server certificate is verified against tls_ca and the API key is never sent in plaintext", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host (the admin API endpoint must be an https URL like https://host:port)")
	}
	return nil
}
