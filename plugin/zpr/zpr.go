// Package zpr answers AAAA queries for <service>.<zone> by asking the ZPR
// visa service admin API (GET /admin/services/{name}) and returning the
// service's zpr_addr. It is stateless per query; positive caching is left to
// CoreDNS's stock cache plugin.
package zpr

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// Zpr is the plugin handler. One instance serves one zone (from the server
// block).
type Zpr struct {
	Next  plugin.Handler
	Zones []string

	// Endpoint is the admin API base URL, e.g. https://[fd5a:5052::1]:8182.
	Endpoint string
	// TTL is the positive answer TTL in seconds.
	TTL uint32
	// NegativeTTL is the SOA MINIMUM used for negative answers, in seconds.
	NegativeTTL uint32

	apiKey string
	client *http.Client
}

// Name implements plugin.Handler.
func (z *Zpr) Name() string { return "zpr" }

// ServeDNS implements plugin.Handler per the name-semantics table:
// apex SOA/NS synthesized; one label under the zone -> service lookup
// (AAAA -> zpr_addr, other types NODATA); two or more labels -> NXDOMAIN
// without an HTTP call; 404 -> NXDOMAIN; any other admin API failure ->
// SERVFAIL; out-of-zone -> next plugin.
func (z *Zpr) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	zone := plugin.Zones(z.Zones).Matches(state.Name())
	if zone == "" {
		return plugin.NextOrFailure(z.Name(), z.Next, ctx, w, r)
	}

	qname := strings.ToLower(state.Name())
	if qname == zone { // apex
		return z.writeApex(state, zone)
	}

	rel := strings.TrimSuffix(qname, "."+zone)
	if strings.Contains(rel, ".") {
		// Two or more labels under the zone: NXDOMAIN, no HTTP call.
		return z.writeNxdomain(state, zone)
	}

	addr, status, err := z.lookupService(ctx, rel)
	switch status {
	case lookupNotFound:
		return z.writeNxdomain(state, zone)
	case lookupFailure:
		return dns.RcodeServerFailure, plugin.Error(z.Name(), err)
	}

	if state.QType() != dns.TypeAAAA {
		// The name exists but only AAAA is served: NODATA.
		return z.writeNodata(state, zone)
	}
	return z.writeAnswer(state, addr)
}

// Ready implements ready.Readiness with one GET /admin/services. The list
// body is drained (bounded) rather than decoded so the connection is
// reusable; only the status code matters here.
func (z *Zpr) Ready() bool {
	req, err := http.NewRequest(http.MethodGet, z.Endpoint+"/admin/services", nil)
	if err != nil {
		return false
	}
	req.Header.Set("X-API-Key", z.apiKey)
	resp, err := z.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	drainBody(resp.Body)
	return resp.StatusCode == http.StatusOK
}

// soa synthesizes the zone's SOA record. MINIMUM carries the negative TTL
// (RFC 2308 negative caching).
func (z *Zpr) soa(zone string) *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: z.NegativeTTL},
		Ns:      "ns." + zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  z.NegativeTTL,
	}
}

func (z *Zpr) writeAnswer(state request.Request, addr netip.Addr) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	m.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: z.TTL},
		AAAA: addr.AsSlice(),
	}}
	return writeMsg(state, m)
}

func (z *Zpr) writeNodata(state request.Request, zone string) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	m.Ns = []dns.RR{z.soa(zone)}
	return writeMsg(state, m)
}

func (z *Zpr) writeNxdomain(state request.Request, zone string) (int, error) {
	m := new(dns.Msg)
	m.SetRcode(state.Req, dns.RcodeNameError)
	m.Authoritative = true
	m.Ns = []dns.RR{z.soa(zone)}
	return writeMsg(state, m)
}

func (z *Zpr) writeApex(state request.Request, zone string) (int, error) {
	m := new(dns.Msg)
	m.SetReply(state.Req)
	m.Authoritative = true
	switch state.QType() {
	case dns.TypeSOA:
		m.Answer = []dns.RR{z.soa(zone)}
	case dns.TypeNS:
		m.Answer = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: z.TTL},
			Ns:  "ns." + zone,
		}}
	default:
		m.Ns = []dns.RR{z.soa(zone)}
	}
	return writeMsg(state, m)
}

func writeMsg(state request.Request, m *dns.Msg) (int, error) {
	if err := state.W.WriteMsg(m); err != nil {
		return dns.RcodeServerFailure, fmt.Errorf("zpr: writing response: %w", err)
	}
	return m.Rcode, nil
}
