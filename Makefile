.PHONY: build build-shim test lint clean proto
.PHONY: smoke
.PHONY: completions package-snapshot package-release
.PHONY: build-macos-enterprise build-macos-go build-swift assemble-bundle sign-bundle

VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo unknown)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"

GOCACHE ?= $(CURDIR)/.gocache
GOMODCACHE ?= $(CURDIR)/.gomodcache
GOPATH ?= $(CURDIR)/.gopath

build:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh ./cmd/agentsh
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-shell-shim ./cmd/agentsh-shell-shim

build-shim:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-shell-shim ./cmd/agentsh-shell-shim

proto:
	protoc -I proto \
	  --go_out=. --go_opt=module=github.com/agentsh/agentsh \
	  --go-grpc_out=. --go-grpc_opt=module=github.com/agentsh/agentsh \
	  proto/agentsh/v1/pty.proto

test:
	mkdir -p $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go test ./...

smoke:
	bash scripts/smoke.sh

lint:
	@echo "No linter configured"

clean:
	rm -rf bin coverage.out dist

# Generate shell completions
completions: build
	mkdir -p packaging/completions
	bin/agentsh completion bash > packaging/completions/agentsh.bash
	bin/agentsh completion zsh > packaging/completions/agentsh.zsh
	bin/agentsh completion fish > packaging/completions/agentsh.fish

# Build packages locally using goreleaser (snapshot mode, no publish)
package-snapshot: completions
	goreleaser release --snapshot --clean --skip=publish

# Build release packages (requires GITHUB_TOKEN, usually run by CI)
package-release:
	goreleaser release --clean

# =============================================================================
# macOS Enterprise Build (System Extension + Network Extension)
# NOTE: build-swift, assemble-bundle, and sign-bundle require macOS with Xcode
# =============================================================================

# Build Go binary for macOS (CGO disabled for cross-compilation; Swift handles platform-specific code)
build-macos-go:
	mkdir -p build/AgentSH.app/Contents/MacOS build/AgentSH-amd64.app/Contents/MacOS
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o build/AgentSH.app/Contents/MacOS/agentsh ./cmd/agentsh
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o build/AgentSH-amd64.app/Contents/MacOS/agentsh ./cmd/agentsh

# Build Swift components (requires Xcode)
build-swift:
	xcodebuild -project macos/AgentSH.xcodeproj -scheme SysExt -configuration Release
	xcodebuild -project macos/AgentSH.xcodeproj -scheme XPCService -configuration Release

# Assemble app bundle
assemble-bundle: build-macos-go build-swift
	mkdir -p build/AgentSH.app/Contents/{Library/SystemExtensions,XPCServices,Resources}
	cp macos/AgentSH/Info.plist build/AgentSH.app/Contents/
	cp -r build/Release/com.agentsh.sysext.systemextension build/AgentSH.app/Contents/Library/SystemExtensions/
	cp -r build/Release/com.agentsh.xpc.xpc build/AgentSH.app/Contents/XPCServices/

# Sign bundle (requires signing identity)
sign-bundle:
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/SysExt/SysExt.entitlements \
		build/AgentSH.app/Contents/Library/SystemExtensions/com.agentsh.sysext.systemextension
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app/Contents/XPCServices/com.agentsh.xpc.xpc
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app

# Full enterprise build
build-macos-enterprise: assemble-bundle sign-bundle
	@echo "Enterprise build complete: build/AgentSH.app"
