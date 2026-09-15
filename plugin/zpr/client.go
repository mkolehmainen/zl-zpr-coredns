package zpr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

// lookupStatus classifies the outcome of an admin API service lookup.
type lookupStatus int

const (
	// lookupFound: 200 with valid JSON and a parseable zpr_addr.
	lookupFound lookupStatus = iota
	// lookupNotFound: 404 — no such service. Maps to NXDOMAIN.
	lookupNotFound
	// lookupFailure: anything else — 5xx, 401/403, transport error,
	// non-JSON body, unparseable zpr_addr. Maps to SERVFAIL, never NXDOMAIN.
	lookupFailure
)

// serviceAddr is the slice of ServiceDescriptor (Contract 1) the plugin
// consumes. Only zpr_addr is decoded; every other field is deliberately
// ignored so future additions to the descriptor do not break the plugin.
type serviceAddr struct {
	ZprAddr string `json:"zpr_addr"`
}

// lookupService resolves a service name via GET /admin/services/{name}.
// The name must already be lowercased; it is URL-path-encoded here.
func (z *Zpr) lookupService(ctx context.Context, name string) (netip.Addr, lookupStatus, error) {
	u := z.Endpoint + "/admin/services/" + url.PathEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return netip.Addr{}, lookupFailure, err
	}
	req.Header.Set("X-API-Key", z.apiKey)

	resp, err := z.client.Do(req)
	if err != nil {
		return netip.Addr{}, lookupFailure, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return netip.Addr{}, lookupNotFound, nil
	case resp.StatusCode != http.StatusOK:
		return netip.Addr{}, lookupFailure, fmt.Errorf("admin API returned %s for %q", resp.Status, name)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return netip.Addr{}, lookupFailure, err
	}
	var sd serviceAddr
	if err := json.Unmarshal(body, &sd); err != nil {
		return netip.Addr{}, lookupFailure, fmt.Errorf("admin API body for %q is not valid JSON: %w", name, err)
	}
	addr, err := netip.ParseAddr(sd.ZprAddr)
	if err != nil {
		return netip.Addr{}, lookupFailure, fmt.Errorf("admin API zpr_addr %q for %q: %w", sd.ZprAddr, name, err)
	}
	return addr, lookupFound, nil
}

// readAPIKey reads the API key file, stripping a trailing newline.
func readAPIKey(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	key := strings.TrimRight(string(b), "\r\n")
	if key == "" {
		return "", fmt.Errorf("api_key_file %s is empty", path)
	}
	return key, nil
}
