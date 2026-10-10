# PiLens build. Produces a self-contained arm64 package; nothing is compiled on the Pi.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOARCH  ?= arm64
PKG     := pilens-$(VERSION)-linux-$(GOARCH)
LDFLAGS := -s -w -X main.Version=$(VERSION)
GO      := CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go

.PHONY: all web build package test test-docker test-netns clean

all: package

web:
	cd web && npm ci --no-audit --no-fund && npm run build
	touch web/dist/.gitkeep

build: web
	mkdir -p dist/$(PKG)/bin
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(PKG)/bin/pilens ./cmd/pilens
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/$(PKG)/bin/pilens-helper ./cmd/pilens-helper

package: build
	cp -r systemd packaging/setup.example.yaml packaging/mitm_addon.py dist/$(PKG)/
	cp scripts/*.sh dist/$(PKG)/
	cp -r docs README.md LICENSE dist/$(PKG)/
	echo $(VERSION) > dist/$(PKG)/VERSION
	cd dist && tar --owner=0 --group=0 -czf $(PKG).tar.gz $(PKG) && sha256sum $(PKG).tar.gz > $(PKG).tar.gz.sha256
	@echo "package: dist/$(PKG).tar.gz"

# Unit tests that need no external tools.
test:
	go vet ./...
	go test ./...
	cd web && npx tsc --noEmit

# Capture/tshark and namespace tests inside a Debian trixie container (mirrors Raspberry Pi OS).
test-docker:
	docker build -q -t pilens-test tests/integration
	mkdir -p .testbin
	for p in capture api pcapfile; do CGO_ENABLED=0 go test -c -o .testbin/$$p.test ./internal/$$p; done
	CGO_ENABLED=0 go build -o .testbin/pilens-helper ./cmd/pilens-helper
	CGO_ENABLED=0 go build -o .testbin/pilens ./cmd/pilens
	docker run --rm --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
	  -e PILENS_LIVE_TEST=1 -v $(CURDIR):/src:ro -v $(CURDIR)/.testbin:/t:ro pilens-test /src/tests/integration/run.sh

clean:
	rm -rf dist .testbin web/node_modules
