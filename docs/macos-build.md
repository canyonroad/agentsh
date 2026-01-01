# macOS Build Guide

This guide covers building agentsh for macOS, including both FUSE-T (standard) and ESF+NE (enterprise) modes.

## Build Modes

| Mode | Security Score | Requirements | Use Case |
|------|:-------------:|--------------|----------|
| **ESF+NE** | 90% | Apple entitlements, Xcode 15+ | Enterprise/commercial products |
| **FUSE-T** | 70% | `brew install fuse-t`, CGO | Development, personal use |
| **Observation** | 25% | None | Testing, audit-only |

## FUSE-T Build (Standard)

FUSE-T provides file policy enforcement without requiring Apple entitlements.

### Prerequisites

```bash
# Install FUSE-T
brew install fuse-t

# Verify installation
ls /usr/local/lib/libfuse-t.dylib
```

### Build

```bash
# Build with CGO (required for FUSE-T)
CGO_ENABLED=1 go build -o bin/agentsh ./cmd/agentsh

# Build shell shim
go build -o bin/agentsh-shell-shim ./cmd/agentsh-shell-shim
```

### Verify

```bash
./bin/agentsh --version
./bin/agentsh server --help
```

## ESF+NE Build (Enterprise)

ESF+NE provides near-Linux-level enforcement using Apple's Endpoint Security Framework and Network Extension.

### Prerequisites

1. **Apple Developer Program membership** - Required for entitlements
2. **ESF + Network Extension entitlements** - Request from Apple with business justification
3. **Xcode 15+** - For building Swift components
4. **Code signing identity** - Developer ID or Apple Development certificate

### Verify Prerequisites

```bash
# Check Xcode version
xcodebuild -version
# Should be 15.0 or higher

# Check Swift version
swift --version
# Should be 5.9 or higher

# List code signing identities
security find-identity -v -p codesigning
```

### Build Steps

#### 1. Build Go Binary for macOS

```bash
# Build for Apple Silicon (arm64)
make build-macos-go

# This creates:
# - build/AgentSH.app/Contents/MacOS/agentsh (arm64)
# - build/AgentSH-amd64.app/Contents/MacOS/agentsh (amd64)
```

#### 2. Build Swift Components

```bash
# Build System Extension and XPC Service
make build-swift

# This builds:
# - com.agentsh.sysext.systemextension
# - com.agentsh.xpc.xpc
```

#### 3. Assemble App Bundle

```bash
# Combine Go + Swift into app bundle
make assemble-bundle
```

#### 4. Sign the Bundle

```bash
# Sign with your Developer ID
SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)" make sign-bundle

# Or for development
SIGNING_IDENTITY="Apple Development" make sign-bundle
```

#### Full Enterprise Build

```bash
# One-command build (requires all prerequisites)
SIGNING_IDENTITY="Developer ID Application" make build-macos-enterprise
```

### Output Structure

```
build/AgentSH.app/
├── Contents/
│   ├── Info.plist
│   ├── MacOS/
│   │   └── agentsh                    # Go binary
│   ├── Library/
│   │   └── SystemExtensions/
│   │       └── com.agentsh.sysext.systemextension/
│   │           ├── Contents/
│   │           │   ├── MacOS/
│   │           │   │   └── com.agentsh.sysext  # ESF + NE
│   │           │   └── Info.plist
│   └── XPCServices/
│       └── com.agentsh.xpc.xpc/
│           ├── Contents/
│           │   ├── MacOS/
│           │   │   └── com.agentsh.xpc  # XPC bridge
│           │   └── Info.plist
```

## System Extension Approval

After installing the ESF+NE app bundle, users must approve the System Extension:

1. **First launch** - macOS will prompt "System Extension Blocked"
2. **Open System Settings** > General > Login Items & Extensions
3. **Allow** the agentsh System Extension
4. **Restart may be required** for Network Extension activation

This is a one-time approval per machine.

## Graceful Fallback

The ESF+NE binary automatically detects available entitlements:

1. **With entitlements** - Uses ESF for file/process, Network Extension for network
2. **Without entitlements** - Falls back to FUSE-T mode
3. **Without FUSE-T** - Falls back to observation-only mode

No code changes required - fallback is automatic at runtime.

## Troubleshooting

### Build Errors

**"Xcode not found"**
```bash
xcode-select --install
sudo xcode-select -s /Applications/Xcode.app
```

**"No signing identity found"**
```bash
# List available identities
security find-identity -v -p codesigning

# Use a valid identity
SIGNING_IDENTITY="Apple Development: you@email.com (TEAMID)" make sign-bundle
```

**"Entitlement not allowed"**
- ESF and Network Extension entitlements must be provisioned by Apple
- Apply at developer.apple.com with business justification

### Runtime Errors

**"System Extension blocked"**
- User must approve in System Settings > General > Login Items & Extensions

**"XPC connection failed"**
- Verify System Extension is approved and running
- Check Console.app for XPC errors

**"ESF client initialization failed"**
- App must be signed with valid ESF entitlements
- Check code signing: `codesign -dv --entitlements - AgentSH.app`

## Cross-Compilation

Building macOS binaries from Linux (Go only, not Swift):

```bash
# For Apple Silicon
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o agentsh-darwin-arm64 ./cmd/agentsh

# For Intel Mac
GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o agentsh-darwin-amd64 ./cmd/agentsh
```

**Note:** CGO_ENABLED=0 means no FUSE-T support. The binary will run in observation-only mode. Swift components (ESF+NE) must be built on macOS.

## See Also

- [macOS ESF+NE Architecture](macos-esf-ne-architecture.md) - Technical architecture details
- [Platform Comparison](platform-comparison.md) - Feature comparison across platforms
- [Cross-Platform Notes](cross-platform.md) - Quick start for all platforms
