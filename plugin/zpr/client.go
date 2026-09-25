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

// lookupStatus classifies the outcome of an admin API name lookup
// (service or host).
type lookupStatus int

const (
	// lookupFound: 200 with valid JSON and a parseable zpr_addr.
	lookupFound lookupStatus = iota
	// lookupNotFound: 404 — no such name in that namespace. After the
	// service lookup it means "try hosts"; after the host lookup it maps
	// to NXDOMAIN.
	lookupNotFound
	// lookupFailure: anything else — 5xx, 401/403, transport error,
	// non-JSON body, unparseable zpr_addr. Maps to SERVFAIL, never NXDOMAIN.
	lookupFailure
)

// serviceAddr is the slice of ServiceDescriptor — and equally of
// HostDescriptor (both in zl-zpr-visaservice/admin-http-api.txt; see
// README.md, "Admin API consumed") — that the plugin consumes. Only
// zpr_addr is decoded; every other field is deliberately ignored so future
// additions to either descriptor do not break the plugin.
type serviceAddr struct {
	ZprAddr string `json:"zpr_addr"`
}

// maxBodyBytes bounds how much of an admin API response body is read —
// both when decoding it and when draining it before close so the
// underlying connection can be reused.
const maxBodyBytes = 1 << 20

// drainBody consumes up to maxBodyBytes of an unread response body so the
// Transport sees EOF and returns the connection to the idle pool. Without
// this, every non-success early return (404s on nonexistent names are
// normal and high-volume) closes the connection and forces a fresh
// TCP+TLS handshake on the next lookup.
func drainBody(body io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxBodyBytes))
}

// lookupService resolves a service name via GET /admin/services/{name}.
// The name must already be lowercased; it is URL-path-encoded here.
func (z *Zpr) lookupService(ctx context.Context, name string) (netip.Addr, lookupStatus, error) {
	return z.lookup(ctx, "/admin/services/", name)
}

// lookupHost resolves a machine (host) name via GET /admin/hosts/{name}.
// The name must already be lowercased; it is URL-path-encoded here.
func (z *Zpr) lookupHost(ctx context.Context, name string) (netip.Addr, lookupStatus, error) {
	return z.lookup(ctx, "/admin/hosts/", name)
}

// lookup performs one admin API name lookup under the given path prefix.
// Status mapping, body limiting, draining and zpr_addr decoding are shared
// by the service and host lookups, which differ only in the path.
func (z *Zpr) lookup(ctx context.Context, pathPrefix, name string) (netip.Addr, lookupStatus, error) {
	u := z.Endpoint + pathPrefix + url.PathEscape(name)
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
		drainBody(resp.Body)
		return netip.Addr{}, lookupNotFound, nil
	case resp.StatusCode != http.StatusOK:
		drainBody(resp.Body)
		return netip.Addr{}, lookupFailure, fmt.Errorf("admin API returned %s for %q", resp.Status, name)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return netip.Addr{}, lookupFailure, err
	}
	drainBody(resp.Body) // discard anything past the limit so the conn is reusable
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
