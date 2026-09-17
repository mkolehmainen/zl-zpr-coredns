package zpr

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// fullDescriptor is a complete ServiceDescriptor as served by the admin API
// (Contract 1). The plugin must read only zpr_addr and ignore the rest.
const fullDescriptor = `{
	"service_name": "web",
	"actor_cn": "web.zpr",
	"zpr_addr": "fd5a:5052:adda:1::7",
	"dock_zpr_addr": "fd5a:5052:adda:1::1",
	"service_kind": "http",
	"service_endpoints": "80/tcp"
}`

type fakeReq struct {
	method     string
	path       string
	apiKey     string
	remoteAddr string
}

// route is one scripted admin API response, keyed by the path prefix that
// selects it (e.g. "/admin/services/" vs "/admin/hosts/").
type route struct {
	status int
	body   string
}

// fakeAdmin is a scripted admin API that records every request it receives.
// When routes is set, a request is answered by the route whose key prefixes
// its path; otherwise the single default status/body answers everything.
type fakeAdmin struct {
	ts *httptest.Server

	mu     sync.Mutex
	reqs   []fakeReq
	status int
	body   string
	routes map[string]route
}

func newFakeAdmin(t *testing.T, status int, body string) *fakeAdmin {
	t.Helper()
	return startFakeAdmin(t, &fakeAdmin{status: status, body: body})
}

func newFakeAdminRoutes(t *testing.T, routes map[string]route) *fakeAdmin {
	t.Helper()
	return startFakeAdmin(t, &fakeAdmin{routes: routes})
}

func startFakeAdmin(t *testing.T, f *fakeAdmin) *fakeAdmin {
	t.Helper()
	f.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, fakeReq{
			method:     r.Method,
			path:       r.URL.Path,
			apiKey:     r.Header.Get("X-API-Key"),
			remoteAddr: r.RemoteAddr,
		})
		status, body := f.status, f.body
		for prefix, rt := range f.routes {
			if strings.HasPrefix(r.URL.Path, prefix) {
				status, body = rt.status, rt.body
				break
			}
		}
		f.mu.Unlock()
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(f.ts.Close)
	return f
}

func (f *fakeAdmin) requests() []fakeReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeReq(nil), f.reqs...)
}

const testKey = "test-resolve-key"

func newTestZpr(endpoint string) *Zpr {
	return &Zpr{
		Zones:       []string{"zpr."},
		Endpoint:    endpoint,
		TTL:         42,
		NegativeTTL: 7,
		apiKey:      testKey,
		client:      &http.Client{Timeout: 2 * time.Second},
	}
}

func query(t *testing.T, z *Zpr, qname string, qtype uint16) (int, *dns.Msg) {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(qname, qtype)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := z.ServeDNS(context.Background(), rec, req)
	if rcode == dns.RcodeServerFailure {
		if err == nil {
			t.Fatalf("SERVFAIL with nil error for %s", qname)
		}
		return rcode, rec.Msg
	}
	if err != nil {
		t.Fatalf("ServeDNS(%s) error: %v", qname, err)
	}
	if rec.Msg != nil {
		return rec.Msg.Rcode, rec.Msg
	}
	return rcode, nil
}

func soaFromAuthority(t *testing.T, m *dns.Msg) *dns.SOA {
	t.Helper()
	for _, rr := range m.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa
		}
	}
	t.Fatalf("no SOA in authority section: %v", m.Ns)
	return nil
}

func TestAAAAFound(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "web.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
	aaaa, ok := m.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", m.Answer[0])
	}
	if got, want := aaaa.AAAA.String(), "fd5a:5052:adda:1::7"; got != want {
		t.Errorf("AAAA = %s, want %s", got, want)
	}
	if aaaa.Hdr.Ttl != z.TTL {
		t.Errorf("TTL = %d, want %d", aaaa.Hdr.Ttl, z.TTL)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("admin API requests = %d, want 1", len(reqs))
	}
	if reqs[0].method != http.MethodGet || reqs[0].path != "/admin/services/web" {
		t.Errorf("request = %s %s, want GET /admin/services/web", reqs[0].method, reqs[0].path)
	}
	if reqs[0].apiKey != testKey {
		t.Errorf("X-API-Key = %q, want %q", reqs[0].apiKey, testKey)
	}
}

func TestAOnExistingNameIsNodata(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "web.zpr.", dns.TypeA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 0 {
		t.Fatalf("answers = %d, want 0 (NODATA)", len(m.Answer))
	}
	soaFromAuthority(t, m)
}

func TestNotFoundIsNxdomain(t *testing.T) {
	f := newFakeAdmin(t, http.StatusNotFound, `not found`)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "nope.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", rcode)
	}
	soa := soaFromAuthority(t, m)
	if soa.Minttl != z.NegativeTTL {
		t.Errorf("SOA MINIMUM = %d, want %d", soa.Minttl, z.NegativeTTL)
	}
}

func TestMultiLabelIsNxdomainWithoutHTTPCall(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "a.b.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", rcode)
	}
	soaFromAuthority(t, m)
	if got := len(f.requests()); got != 0 {
		t.Fatalf("admin API requests = %d, want 0", got)
	}
}

func TestNameIsLowercasedBeforeLookup(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, _ := query(t, z, "WEB.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("admin API requests = %d, want 1", len(reqs))
	}
	if got, want := reqs[0].path, "/admin/services/web"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
}

func TestAdminAPIFailuresAreServfail(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, "boom"},
		{"401", http.StatusUnauthorized, "no key"},
		{"403", http.StatusForbidden, "denied"},
		{"non-JSON body", http.StatusOK, "<html>not json</html>"},
		{"bad zpr_addr", http.StatusOK, `{"zpr_addr": "not-an-address"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAdmin(t, tc.status, tc.body)
			z := newTestZpr(f.ts.URL)
			rcode, _ := query(t, z, "web.zpr.", dns.TypeAAAA)
			if rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %d, want SERVFAIL", rcode)
			}
		})
	}

	t.Run("connection refused", func(t *testing.T) {
		f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
		url := f.ts.URL
		f.ts.Close() // now unreachable
		z := newTestZpr(url)
		rcode, _ := query(t, z, "web.zpr.", dns.TypeAAAA)
		if rcode != dns.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL", rcode)
		}
	})
}

func TestApexSOA(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "zpr.", dns.TypeSOA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.SOA); !ok {
		t.Fatalf("answer is %T, want *dns.SOA", m.Answer[0])
	}
	if got := len(f.requests()); got != 0 {
		t.Fatalf("admin API requests = %d, want 0", got)
	}
}

func TestApexNS(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "zpr.", dns.TypeNS)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
	if _, ok := m.Answer[0].(*dns.NS); !ok {
		t.Fatalf("answer is %T, want *dns.NS", m.Answer[0])
	}
}

func TestOutOfZoneGoesToNextPlugin(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)

	called := false
	z.Next = test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		called = true
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})

	rcode, _ := query(t, z, "example.com.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR from next plugin", rcode)
	}
	if !called {
		t.Fatal("next plugin was not called")
	}
	if got := len(f.requests()); got != 0 {
		t.Fatalf("admin API requests = %d, want 0", got)
	}
}

func TestAPIKeyFileTrailingNewlineStripped(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte(testKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := readAPIKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if key != testKey {
		t.Fatalf("readAPIKey = %q, want %q", key, testKey)
	}

	f := newFakeAdmin(t, http.StatusOK, fullDescriptor)
	z := newTestZpr(f.ts.URL)
	z.apiKey = key
	if rcode, _ := query(t, z, "web.zpr.", dns.TypeAAAA); rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	reqs := f.requests()
	if len(reqs) != 1 || reqs[0].apiKey != testKey {
		t.Fatalf("fake saw X-API-Key %+v, want exactly one request with %q", reqs, testKey)
	}
}

// Compile-time check that Zpr is a plugin.Handler.
var _ plugin.Handler = (*Zpr)(nil)

// remoteAddrs returns the distinct client connections the fake has seen.
// One distinct RemoteAddr across requests means the client reused the
// connection; a body closed before EOF forces a new TCP connection.
func distinctRemoteAddrs(reqs []fakeReq) map[string]bool {
	set := make(map[string]bool)
	for _, r := range reqs {
		set[r.remoteAddr] = true
	}
	return set
}

func TestNotFoundLookupsReuseConnection(t *testing.T) {
	f := newFakeAdmin(t, http.StatusNotFound, `not found`)
	z := newTestZpr(f.ts.URL)

	for i := 0; i < 3; i++ {
		rcode, _ := query(t, z, "nope.zpr.", dns.TypeAAAA)
		if rcode != dns.RcodeNameError {
			t.Fatalf("rcode = %d, want NXDOMAIN", rcode)
		}
		time.Sleep(10 * time.Millisecond) // let the conn return to the idle pool
	}
	reqs := f.requests()
	// Each NXDOMAIN is now two lookups: services 404, then hosts 404.
	if len(reqs) != 6 {
		t.Fatalf("admin API requests = %d, want 6", len(reqs))
	}
	if addrs := distinctRemoteAddrs(reqs); len(addrs) != 1 {
		t.Errorf("404 lookups used %d connections, want 1 (body not drained before close?): %v", len(addrs), addrs)
	}
}

func TestErrorStatusLookupsReuseConnection(t *testing.T) {
	f := newFakeAdmin(t, http.StatusInternalServerError, `boom`)
	z := newTestZpr(f.ts.URL)

	for i := 0; i < 3; i++ {
		rcode, _ := query(t, z, "web.zpr.", dns.TypeAAAA)
		if rcode != dns.RcodeServerFailure {
			t.Fatalf("rcode = %d, want SERVFAIL", rcode)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addrs := distinctRemoteAddrs(f.requests()); len(addrs) != 1 {
		t.Errorf("5xx lookups used %d connections, want 1: %v", len(addrs), addrs)
	}
}

func TestReadyReusesConnection(t *testing.T) {
	f := newFakeAdmin(t, http.StatusOK, `[{"service_name":"web"}]`)
	z := newTestZpr(f.ts.URL)

	for i := 0; i < 3; i++ {
		if !z.Ready() {
			t.Fatal("Ready() = false, want true")
		}
		time.Sleep(10 * time.Millisecond)
	}
	reqs := f.requests()
	if len(reqs) != 3 {
		t.Fatalf("admin API requests = %d, want 3", len(reqs))
	}
	if addrs := distinctRemoteAddrs(reqs); len(addrs) != 1 {
		t.Errorf("Ready() used %d connections, want 1 (list body not drained?): %v", len(addrs), addrs)
	}
}

// fullHostDescriptor is a complete HostDescriptor as served by the admin API
// (master plan §4). The plugin must read only zpr_addr and ignore the rest.
const fullHostDescriptor = `{
	"hostname": "somename",
	"zpr_addr": "fd5a:5052:adda:2::9",
	"actor_cn": "somename.zpr"
}`

// pathsSeen returns the admin API paths the fake saw, in request order.
func pathsSeen(reqs []fakeReq) []string {
	paths := make([]string, len(reqs))
	for i, r := range reqs {
		paths[i] = r.path
	}
	return paths
}

func assertPaths(t *testing.T, reqs []fakeReq, want ...string) {
	t.Helper()
	got := pathsSeen(reqs)
	if len(got) != len(want) {
		t.Fatalf("admin API paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("admin API paths = %v, want %v", got, want)
		}
	}
}

func TestServiceFoundSkipsHostLookup(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusOK, fullDescriptor},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "web.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
	aaaa, ok := m.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", m.Answer[0])
	}
	if got, want := aaaa.AAAA.String(), "fd5a:5052:adda:1::7"; got != want {
		t.Errorf("AAAA = %s, want %s (service address, not host)", got, want)
	}
	assertPaths(t, f.requests(), "/admin/services/web")
}

func TestHostFoundAfterServiceNotFound(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusNotFound, `not found`},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "somename.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 1 {
		t.Fatalf("answers = %d, want 1", len(m.Answer))
	}
	aaaa, ok := m.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("answer is %T, want *dns.AAAA", m.Answer[0])
	}
	if got, want := aaaa.AAAA.String(), "fd5a:5052:adda:2::9"; got != want {
		t.Errorf("AAAA = %s, want %s (the host's zpr_addr)", got, want)
	}
	if aaaa.Hdr.Ttl != z.TTL {
		t.Errorf("TTL = %d, want %d", aaaa.Hdr.Ttl, z.TTL)
	}
	assertPaths(t, f.requests(), "/admin/services/somename", "/admin/hosts/somename")
}

func TestBothNotFoundIsNxdomain(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusNotFound, `not found`},
		"/admin/hosts/":    {http.StatusNotFound, `not found`},
	})
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "nope.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN", rcode)
	}
	soa := soaFromAuthority(t, m)
	if soa.Minttl != z.NegativeTTL {
		t.Errorf("SOA MINIMUM = %d, want %d", soa.Minttl, z.NegativeTTL)
	}
	assertPaths(t, f.requests(), "/admin/services/nope", "/admin/hosts/nope")
}

func TestAOnExistingHostIsNodata(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusNotFound, `not found`},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	rcode, m := query(t, z, "somename.zpr.", dns.TypeA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	if len(m.Answer) != 0 {
		t.Fatalf("answers = %d, want 0 (NODATA)", len(m.Answer))
	}
	soaFromAuthority(t, m)
}

func TestServiceFailureNeverFallsThroughToHosts(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusInternalServerError, `boom`},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	rcode, _ := query(t, z, "web.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %d, want SERVFAIL", rcode)
	}
	assertPaths(t, f.requests(), "/admin/services/web")
}

func TestHostLookupFailuresAreServfail(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{"500", http.StatusInternalServerError, "boom"},
		{"401", http.StatusUnauthorized, "no key"},
		{"non-JSON body", http.StatusOK, "<html>not json</html>"},
		{"bad zpr_addr", http.StatusOK, `{"zpr_addr": "not-an-address"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAdminRoutes(t, map[string]route{
				"/admin/services/": {http.StatusNotFound, `not found`},
				"/admin/hosts/":    {tc.status, tc.body},
			})
			z := newTestZpr(f.ts.URL)
			rcode, _ := query(t, z, "somename.zpr.", dns.TypeAAAA)
			if rcode != dns.RcodeServerFailure {
				t.Fatalf("rcode = %d, want SERVFAIL", rcode)
			}
			assertPaths(t, f.requests(), "/admin/services/somename", "/admin/hosts/somename")
		})
	}
}

func TestHostNameIsLowercasedBeforeLookup(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusNotFound, `not found`},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	rcode, _ := query(t, z, "SOMENAME.zpr.", dns.TypeAAAA)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", rcode)
	}
	assertPaths(t, f.requests(), "/admin/services/somename", "/admin/hosts/somename")
}

func TestHostLookupReusesConnection(t *testing.T) {
	f := newFakeAdminRoutes(t, map[string]route{
		"/admin/services/": {http.StatusNotFound, `not found`},
		"/admin/hosts/":    {http.StatusOK, fullHostDescriptor},
	})
	z := newTestZpr(f.ts.URL)

	for i := 0; i < 3; i++ {
		rcode, _ := query(t, z, "somename.zpr.", dns.TypeAAAA)
		if rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %d, want NOERROR", rcode)
		}
		time.Sleep(10 * time.Millisecond) // let the conn return to the idle pool
	}
	reqs := f.requests()
	if len(reqs) != 6 {
		t.Fatalf("admin API requests = %d, want 6", len(reqs))
	}
	if addrs := distinctRemoteAddrs(reqs); len(addrs) != 1 {
		t.Errorf("service-404-then-host lookups used %d connections, want 1: %v", len(addrs), addrs)
	}
}
