# zl-zpr-coredns

A CoreDNS plugin (`zpr`) that resolves ZPR service names to ZPR addresses.
It answers `AAAA <service>.<zone>` by calling the visa service admin API
`GET /admin/services/{name}` and returning the service's `zpr_addr`. The
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

## Corefile syntax (Contract 3)

```
zpr.:53 {
    zpr {
        endpoint       https://[fd5a:5052::1]:8182   # admin API base URL; default shown
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
block, not the plugin. There is **no** insecure-skip-verify option,
deliberately: the admin API certificate is always verified against `tls_ca`.

## Name semantics

| Query | Behaviour |
|---|---|
| `<service>.<zone>` AAAA | `GET /admin/services/<service>` (name lowercased, URL-path-encoded); 200 → one AAAA with `zpr_addr`, TTL = `ttl` |
| `<service>.<zone>` other type, service exists | NOERROR, no answers, SOA in authority (NODATA) |
| Service not found (404) | NXDOMAIN, SOA in authority with MINIMUM = `negative_ttl` |
| Two or more labels under the zone (`a.b.<zone>`) | NXDOMAIN, **no HTTP call** |
| Admin API failure (5xx, 401/403, unreachable, non-JSON, bad `zpr_addr`) | **SERVFAIL**, never NXDOMAIN |
| `<zone>` SOA / NS | Synthesized apex records |
| Out-of-zone name | Passed to the next plugin |

The plugin reads **only** `zpr_addr` from the `ServiceDescriptor`; every
other field is ignored so future additions do not break it.

Readiness (`Ready()`) probes `GET /admin/services`.

## Admin API consumed (Contract 1)

```
GET {endpoint}/admin/services/{name}     X-API-Key: <key>
  200  ServiceDescriptor { service_name, actor_cn, zpr_addr, dock_zpr_addr, service_kind, service_endpoints }
  401  key missing/malformed/unknown
  403  key lacks permission
  404  no such service, or no current provider
  500  server error
GET {endpoint}/admin/services            (readiness probe only)
  200  NamedListEntry[]  { "id": string }
```

Types live in `zl-zpr-visaservice/admin-api-types/src/admin_api_types.rs`;
the endpoint reference is `zl-zpr-visaservice/admin-http-api.txt`.
