# zl-zpr-coredns build.
#
# `make build` produces bin/coredns: a CoreDNS binary with the `zpr` plugin
# compiled in. It clones CoreDNS at COREDNS_VERSION into work/, installs our
# plugin.cfg, points the zpr plugin module at this checkout, and builds.
#
# ============================ CoreDNS version pin ============================
# CoreDNS is PINNED at v1.14.7. The pin appears in three places that must be
# kept in sync when bumping to a newer CoreDNS release:
#   1. COREDNS_VERSION below.
#   2. plugin.cfg — regenerate it from the new tag's upstream plugin.cfg
#      (https://raw.githubusercontent.com/coredns/coredns/<tag>/plugin.cfg)
#      and re-insert the zpr line after `cache:cache`:
#        zpr:github.com/mkolehmainen/zl-zpr-coredns/plugin/zpr
#   3. go.mod — update github.com/coredns/coredns to the new tag and
#      github.com/miekg/dns (and github.com/coredns/caddy) to the versions the
#      new tag's own go.mod requires, then `go mod tidy`.
# After bumping: `make clean build test` and
# `bin/coredns -plugins | grep -x zpr` must all succeed. (CoreDNS 1.14.x
# lists bare plugin names in -plugins output, without the older dns. prefix.)
# =============================================================================
COREDNS_VERSION := v1.14.7

BINARY      := coredns
BIN_DIR     := bin
BIN         := $(BIN_DIR)/$(BINARY)
WORK_DIR    := work
COREDNS_SRC := $(WORK_DIR)/coredns

GO          := go
GOFLAGS     :=

.DEFAULT_GOAL := build

.PHONY: all
all: clean fmt build

.PHONY: build
build: $(BIN)

$(BIN): $(shell find plugin -name '*.go') go.mod go.sum plugin.cfg
	@mkdir -p $(BIN_DIR)
	@if [ ! -d $(COREDNS_SRC) ]; then \
		git clone --depth 1 --branch $(COREDNS_VERSION) \
			https://github.com/coredns/coredns.git $(COREDNS_SRC); \
	fi
	cp plugin.cfg $(COREDNS_SRC)/plugin.cfg
	cd $(COREDNS_SRC) && \
		$(GO) mod edit \
			-require=github.com/mkolehmainen/zl-zpr-coredns@v0.0.0 \
			-replace=github.com/mkolehmainen/zl-zpr-coredns=$(CURDIR) && \
		$(GO) generate && \
		$(GO) mod tidy && \
		$(GO) build $(GOFLAGS) -o $(CURDIR)/$(BIN) .

.PHONY: test
test:
	$(GO) test ./...

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(WORK_DIR)
