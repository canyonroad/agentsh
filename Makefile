.PHONY: build build-shim test lint clean proto
.PHONY: smoke
.PHONY: completions package-snapshot package-release
.PHONY: build-macos-enterprise build-macos-go build-swift assemble-bundle sign-bundle
.PHONY: build-driver build-driver-debug install-driver uninstall-driver build-windows-full
.PHONY: build-macwrap
.PHONY: build-approval-dialog

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

# Build macwrap (requires macOS with Xcode - uses cgo for darwin-specific code)
build-macwrap:
	mkdir -p bin $(GOCACHE) $(GOMODCACHE) $(GOPATH)
	GOOS=darwin CGO_ENABLED=1 GOCACHE=$(GOCACHE) GOMODCACHE=$(GOMODCACHE) GOPATH=$(GOPATH) go build $(LDFLAGS) -o bin/agentsh-macwrap ./cmd/agentsh-macwrap

# Build ApprovalDialog.app (standalone SwiftUI app for approval dialogs)
# Requires macOS with Xcode Command Line Tools
APPROVAL_DIALOG_SOURCES := \
	macos/ApprovalDialog/ApprovalDialogApp.swift \
	macos/ApprovalDialog/ApprovalView.swift \
	macos/ApprovalDialog/ServerClient.swift \
	macos/ApprovalDialog/ApprovalRequestData.swift

APPROVAL_DIALOG_FRAMEWORKS := -framework SwiftUI -framework AppKit -framework Foundation

build-approval-dialog:
	@echo "Building ApprovalDialog.app..."
	# Create app bundle structure for arm64
	mkdir -p build/ApprovalDialog.app/Contents/MacOS
	mkdir -p build/ApprovalDialog.app/Contents/Resources
	# Create app bundle structure for amd64
	mkdir -p build/ApprovalDialog-amd64.app/Contents/MacOS
	mkdir -p build/ApprovalDialog-amd64.app/Contents/Resources
	# Compile Swift sources for arm64 (macOS 13.0+ required for SwiftUI .tint and .borderedProminent)
	swiftc \
		-sdk $$(xcrun --sdk macosx --show-sdk-path) \
		-target arm64-apple-macosx13.0 \
		$(APPROVAL_DIALOG_FRAMEWORKS) \
		-parse-as-library \
		-o build/ApprovalDialog.app/Contents/MacOS/ApprovalDialog \
		$(APPROVAL_DIALOG_SOURCES)
	# Compile Swift sources for amd64 (macOS 13.0+ required for SwiftUI .tint and .borderedProminent)
	swiftc \
		-sdk $$(xcrun --sdk macosx --show-sdk-path) \
		-target x86_64-apple-macosx13.0 \
		$(APPROVAL_DIALOG_FRAMEWORKS) \
		-parse-as-library \
		-o build/ApprovalDialog-amd64.app/Contents/MacOS/ApprovalDialog \
		$(APPROVAL_DIALOG_SOURCES)
	# Copy Info.plist
	cp macos/ApprovalDialog/Info.plist build/ApprovalDialog.app/Contents/
	cp macos/ApprovalDialog/Info.plist build/ApprovalDialog-amd64.app/Contents/
	@echo "ApprovalDialog.app built successfully"

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
assemble-bundle: build-macos-go build-swift build-approval-dialog
	mkdir -p build/AgentSH.app/Contents/{Library/SystemExtensions,XPCServices,Resources}
	mkdir -p build/AgentSH-amd64.app/Contents/{Library/SystemExtensions,XPCServices,Resources}
	cp macos/AgentSH/Info.plist build/AgentSH.app/Contents/
	cp macos/AgentSH/Info.plist build/AgentSH-amd64.app/Contents/
	cp -r build/Release/com.agentsh.sysext.systemextension build/AgentSH.app/Contents/Library/SystemExtensions/
	cp -r build/Release/com.agentsh.xpc.xpc build/AgentSH.app/Contents/XPCServices/
	# Copy ApprovalDialog.app to Resources
	cp -r build/ApprovalDialog.app build/AgentSH.app/Contents/Resources/
	cp -r build/ApprovalDialog-amd64.app build/AgentSH-amd64.app/Contents/Resources/ApprovalDialog.app

# Sign bundle (requires signing identity)
sign-bundle:
	# Sign system extension
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/SysExt/SysExt.entitlements \
		build/AgentSH.app/Contents/Library/SystemExtensions/com.agentsh.sysext.systemextension
	# Sign XPC service
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app/Contents/XPCServices/com.agentsh.xpc.xpc
	# Sign ApprovalDialog.app (embedded in Resources)
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/ApprovalDialog/ApprovalDialog.entitlements \
		build/AgentSH.app/Contents/Resources/ApprovalDialog.app
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/ApprovalDialog/ApprovalDialog.entitlements \
		build/AgentSH-amd64.app/Contents/Resources/ApprovalDialog.app
	# Sign main app bundle
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH.app
	codesign --force --deep --sign "$(SIGNING_IDENTITY)" \
		build/AgentSH-amd64.app

# Full enterprise build
build-macos-enterprise: assemble-bundle sign-bundle
	@echo "Enterprise build complete: build/AgentSH.app"

# =============================================================================
# Windows Driver Build (Minifilter)
# NOTE: These targets require Windows with WDK installed
# =============================================================================

# Build Windows driver (Release)
build-driver:
	@echo "Building Windows driver (Release)..."
	cd drivers/windows/agentsh-minifilter && scripts/build.cmd Release x64

# Build Windows driver (Debug)
build-driver-debug:
	@echo "Building Windows driver (Debug)..."
	cd drivers/windows/agentsh-minifilter && scripts/build.cmd Debug x64

# Install Windows driver
install-driver:
	@echo "Installing Windows driver..."
	cd drivers/windows/agentsh-minifilter && scripts/install.cmd

# Uninstall Windows driver
uninstall-driver:
	@echo "Uninstalling Windows driver..."
	cd drivers/windows/agentsh-minifilter && scripts/uninstall.cmd

# Full Windows build (Go + driver)
build-windows-full: build-driver
	GOOS=windows GOARCH=amd64 go build -o bin/agentsh.exe ./cmd/agentsh
