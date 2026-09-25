# zl-zpr-coredns

A CoreDNS plugin (`zpr`) that resolves ZPR service and machine (host) names
to ZPR addresses. It answers `AAAA <name>.<zone>` by calling the visa
service admin API — `GET /admin/services/{name}` first, and on a 404 there
`GET /admin/hosts/{name}` — returning the matching record's `zpr_addr`. The
plugin is stateless per query — positive caching is CoreDNS's stock `cache`
plugin, which `plugin.cfg` places directly before `zpr`.

This repository is **not a fork**: it is a standalone Go module. Unlike the
other `zl-zpr-*` repositories, the working and default branch is **`main`**
and PRs target `main`; there is no upstream mirror branch.

## CoreDNS version pin

CoreDNS is **pinned at `v1.14.7`**. The pin lives in three places that must
move together when re-syncing to a newer CoreDNS release:

1. `COREDNS_VERSION` in the `Makefile` (the tag `make build` clones).
2. `plugin.cfg` — this is upstream's `plugin.cfg` from the pinned tag with
   one line inserted after `cache:cache`:

   ```
   zpr:github.com/mkolehmainen/zl-zpr-coredns/plugin/zpr
   ```

   To re-sync, fetch the new tag's file from
   `https://raw.githubusercontent.com/coredns/coredns/<tag>/plugin.cfg` and
   re-insert that line in the same position (after `cache`, before
   `forward` — order in that file is execution order).
3. `go.mod` — bump `github.com/coredns/coredns` to the new tag, and set
   `github.com/miekg/dns` and `github.com/coredns/caddy` to the versions the
   new tag's own `go.mod` requires; then `go mod tidy`.

After a bump, verify: `make clean build test` and
`bin/coredns -plugins | grep -x zpr`.

## Building

```sh
make build      # clones CoreDNS v1.14.7 into work/, builds bin/coredns
make test       # go test ./...
make clean      # removes bin/ and work/
```

Verify the plugin is compiled in:

```sh
bin/coredns -plugins | grep -x zpr
```

No container image is built here — the demo bakes `bin/coredns` into its own
image.

## Setting it up

Two files must exist before CoreDNS will start, and one decision is yours to
make.

### The decision: which DNS suffix ZPR service names live under

In a Corefile the text before the port is a **DNS zone**, not a keyword. The
stanza below starts `zpr.:53`, which means this server is authoritative for
the zone `zpr.`, so it answers names ending in `.zpr`: a query for
`AAAA web.zpr` looks up the service `web`. The plugin itself never names a
zone — it takes the zone from the server block, strips it, and uses the single
remaining label as the service name.

Pick any suffix and use it consistently:

| Server block key | Query that resolves | Service looked up |
|---|---|---|
| `zpr.:53` | `web.zpr` | `web` |
| `demo.:53` | `web.demo` | `web` |
| `svc.example.com.:53` | `web.svc.example.com` | `web` |

`zl-zpr-demo/dns-demo` uses `demo.`. Exactly one label may precede the zone:
`a.b.demo` is NXDOMAIN, never a lookup for `a.b`.

### The two required files

`api_key_file` — an admin API key with the least-privilege `resolve`
permission, minted on the visa service host with `vsapikey`:

```sh
vsapikey create resolve dns /path/to/vs_keys.toml > /run/secrets/vs-resolve-key
chmod 0600 /run/secrets/vs-resolve-key
```

Use `create --init` instead of `create` if the keys file does not exist yet.
The file holds the key string and nothing else (a trailing newline is
stripped), and is read once, at startup.

`tls_ca` — the PEM certificate or bundle that the admin API's TLS certificate
is verified against; copy the visa service's admin TLS cert. There is no way
to skip this verification. If that certificate is issued for a name rather
than for the endpoint's IP literal, also set `tls_servername` to that name
(the demo PKI issues `vs.zpr`).

Everything else has a usable default, so a minimal config is the zone plus
those two paths:

```
zpr.:53 {
    zpr {
        api_key_file /run/secrets/vs-resolve-key
        tls_ca       /etc/zpr/admin-tls-cert.pem
    }
    cache 30
    errors
    log
}
```

## Running it

CoreDNS has no install step and no configuration beyond the Corefile: the
binary reads `./Corefile` from its working directory, or whatever `-conf`
names.

```sh
bin/coredns                            # uses ./Corefile
bin/coredns -conf /etc/zpr/Corefile
```

Port 53 is privileged, so run as root, grant the binary the capability once,
or serve on a high port while testing:

```sh
sudo setcap cap_net_bind_service=+ep bin/coredns   # then run unprivileged
bin/coredns -dns.port 1053                         # overrides the port in every server block
```

The server listens on **all** interfaces by default. To answer only on the
resolver's overlay address, add the stock `bind` plugin to the server block:

```
bind fd5a:5052:8888::53
```

CoreDNS must also be able to *reach* the admin API endpoint, which means
running it on a host inside the ZPRnet holding a visa that allows it to reach
the `vs-admin` service — see the policy fixture in `dns-demo`.

Verify a running server:

```sh
dig @127.0.0.1 -p 1053 AAAA web.zpr +short   # -> the service's zpr_addr
dig @127.0.0.1 -p 1053 SOA zpr.              # -> the synthesized apex SOA
```

Adding `ready` to the server block exposes `http://localhost:8181/ready`,
which returns 200 only once this plugin's `GET /admin/services` probe
succeeds — a usable container health check.

Clients resolve these names only once their stub resolver points at this
server (`/etc/resolv.conf`, systemd-resolved per-link DNS, or equivalent);
nothing in ZPR configures that for them.

`zl-zpr-demo/dns-demo` is a complete worked example: container, key minting,
policy, and an end-to-end `dig` test.

## Corefile syntax

```
zpr.:53 {
    zpr {
        endpoint       https://[fd5a:5052::1]:8182   # admin API base URL; must be https (rejected at startup otherwise); default shown
        api_key_file   /run/secrets/vs-resolve-key   # required; file contents = key string, trailing newline stripped
        tls_ca         /etc/zpr/admin-tls-cert.pem   # required; PEM bundle used to verify the admin cert
        tls_servername vs.zpr                        # optional; SNI/verify name when the cert is not for the IP
        ttl            30                            # optional; positive TTL seconds
        negative_ttl   10                            # optional; SOA MINIMUM
        timeout        2s                            # optional; per-request HTTP timeout
    }
    cache 30
    errors
    log
}
```

`zpr` may appear **once** per server block. The zone comes from the server
block, not the plugin: `zpr.:53` above serves `<service>.zpr`. There is
**no** insecure-skip-verify option, deliberately: the admin API
certificate is always verified against `tls_ca`.

## Name semantics

| Query | Behaviour |
|---|---|
| `<name>.<zone>` AAAA | `GET /admin/services/<name>` (name lowercased, URL-path-encoded); on 404, `GET /admin/hosts/<name>`; 200 → one AAAA with `zpr_addr`, TTL = `ttl` |
| `<name>.<zone>` other type, name exists (service or host) | NOERROR, no answers, SOA in authority (NODATA) |
| Neither service nor host found (404 + 404) | NXDOMAIN, SOA in authority with MINIMUM = `negative_ttl` |
| Two or more labels under the zone (`a.b.<zone>`) | NXDOMAIN, **no HTTP call** |
| Admin API failure (5xx, 401/403, unreachable, non-JSON, bad `zpr_addr`) | **SERVFAIL**, never NXDOMAIN |
| `<zone>` SOA / NS | Synthesized apex records |
| Out-of-zone name | Passed to the next plugin |

### Resolution order

Services and machine names share **one flat namespace** under the zone, and
a service name always wins — the service lookup runs first, and the host
lookup is attempted only when the service lookup answered a clean 404:

| service lookup | host lookup | answer |
|---|---|---|
| found | (not attempted) | AAAA `zpr_addr`, or NODATA for non-AAAA |
| 404 | found | AAAA `zpr_addr`, or NODATA for non-AAAA |
| 404 | 404 | NXDOMAIN + SOA |
| failure | (not attempted) | SERVFAIL |
| 404 | failure | SERVFAIL |

A *failed* (non-404) service lookup never falls through to hosts: a
hostname can never shadow or substitute for a service, even when the
service lookup is erroring.

The plugin reads **only** `zpr_addr` from the `ServiceDescriptor` and
`HostDescriptor`; every other field is ignored so future additions do not
break it.

Readiness (`Ready()`) probes `GET /admin/services`.

## Admin API consumed

```
GET {endpoint}/admin/services/{name}     X-API-Key: <key>
  200  ServiceDescriptor { service_name, actor_cn, zpr_addr, dock_zpr_addr, service_kind, service_endpoints }
  401  key missing/malformed/unknown
  403  key lacks permission
  404  no such service, or no current provider
  500  server error
GET {endpoint}/admin/hosts/{name}        X-API-Key: <key>
  200  HostDescriptor { hostname, zpr_addr, actor_cn }
  401/403/404/500 as above
GET {endpoint}/admin/services            (readiness probe only)
  200  NamedListEntry[]  { "id": string }
```

Types live in `zl-zpr-visaservice/admin-api-types/src/admin_api_types.rs`;
the endpoint reference is `zl-zpr-visaservice/admin-http-api.txt`.
