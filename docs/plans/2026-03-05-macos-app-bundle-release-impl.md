# macOS App Bundle Release Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace standalone macOS CLI binary signing with a signed, notarized universal app bundle (DMG) in the release pipeline.

**Architecture:** The `sign-macos` job in `release.yml` becomes `build-macos-app`. It downloads GoReleaser's darwin arm64 + amd64 tarballs, lipo's Go binaries into universals, builds Swift targets via xcodebuild, assembles the `.app` bundle, signs inside-out, notarizes, creates DMG, and replaces the darwin tarballs on the release.

**Tech Stack:** GitHub Actions, xcodebuild, lipo, codesign, notarytool, hdiutil, gh CLI

**Design doc:** `docs/plans/2026-03-05-macos-app-bundle-release-design.md`

---

### Task 1: Replace `sign-macos` Job in release.yml

**Files:**
- Modify: `.github/workflows/release.yml:146-228` (replace `sign-macos` job)

**Step 1: Replace the sign-macos job**

Replace the entire `sign-macos` job (lines 146-228) with the new `build-macos-app` job. The new job:
- Runs on `macos-15` (Apple Silicon runner with Xcode 16+)
- No matrix strategy (single job, universal binary)
- Depends on `goreleaser`
- Uses `environment: build` for secrets access

```yaml
  # Build, sign, and notarize macOS app bundle with system extension.
  build-macos-app:
    runs-on: macos-15
    needs: goreleaser
    environment: build
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@v4

      - name: Select Xcode
        run: |
          # Use latest available Xcode on the runner
          sudo xcode-select -s /Applications/Xcode.app/Contents/Developer
          xcodebuild -version

      - name: Import signing certificate
        env:
          MACOS_SIGNING_CERT_P12: ${{ secrets.MACOS_SIGNING_CERT_P12 }}
          MACOS_SIGNING_CERT_PASSWORD: ${{ secrets.MACOS_SIGNING_CERT_PASSWORD }}
        run: |
          echo "$MACOS_SIGNING_CERT_P12" | base64 --decode > cert.p12
          KEYCHAIN="build.keychain"
          KEYCHAIN_PASSWORD="actions"
          security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
          security default-keychain -s "$KEYCHAIN"
          security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
          security import cert.p12 -k "$KEYCHAIN" -P "$MACOS_SIGNING_CERT_PASSWORD" -T /usr/bin/codesign
          security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN"
          rm cert.p12

      - name: Download darwin archives from GoReleaser
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ github.ref_name }}
        run: |
          for arch in amd64 arm64; do
            ARCHIVE="agentsh_${VERSION#v}_darwin_${arch}.tar.gz"
            gh release download "$VERSION" \
              --pattern "$ARCHIVE" \
              --repo "${{ github.repository }}" \
              --dir .
            mkdir -p "unsigned-${arch}"
            tar -xzf "$ARCHIVE" -C "unsigned-${arch}"
          done

      - name: Create universal Go binaries
        run: |
          mkdir -p build/AgentSH.app/Contents/MacOS
          # Lipo each Mach-O binary into a universal
          for bin in unsigned-arm64/agentsh*; do
            name=$(basename "$bin")
            [ -f "$bin" ] || continue
            file "$bin" | grep -q "Mach-O" || continue
            amd64_bin="unsigned-amd64/${name}"
            if [ -f "$amd64_bin" ]; then
              lipo -create -output "build/AgentSH.app/Contents/MacOS/${name}" \
                "$bin" "$amd64_bin"
              echo "Created universal binary: ${name}"
            else
              cp "$bin" "build/AgentSH.app/Contents/MacOS/${name}"
              echo "Copied arm64-only binary: ${name}"
            fi
          done
          # Verify universals
          for bin in build/AgentSH.app/Contents/MacOS/*; do
            echo "--- $(basename "$bin") ---"
            lipo -info "$bin"
          done

      - name: Build Swift targets (universal)
        run: |
          xcodebuild \
            -project macos/agentsh/agentsh.xcodeproj \
            -scheme agentsh \
            -configuration Release \
            -derivedDataPath build/DerivedData \
            ARCHS="arm64 x86_64" \
            ONLY_ACTIVE_ARCH=NO \
            CODE_SIGN_IDENTITY="" \
            CODE_SIGNING_REQUIRED=NO \
            CODE_SIGNING_ALLOWED=NO

      - name: Assemble app bundle
        run: |
          # Copy Info.plist for host app
          cp macos/AgentSH-files/Info.plist build/AgentSH.app/Contents/

          # Copy Swift build products from DerivedData
          PRODUCTS="build/DerivedData/Build/Products/Release"

          # System Extension
          mkdir -p "build/AgentSH.app/Contents/Library/SystemExtensions"
          cp -R "${PRODUCTS}/SysExt.systemextension" \
            "build/AgentSH.app/Contents/Library/SystemExtensions/"

          # XPC Service
          mkdir -p "build/AgentSH.app/Contents/XPCServices"
          cp -R "${PRODUCTS}/xpc.xpc" \
            "build/AgentSH.app/Contents/XPCServices/"

          # Approval Dialog
          mkdir -p "build/AgentSH.app/Contents/Resources"
          cp -R "${PRODUCTS}/approval-dialog.app" \
            "build/AgentSH.app/Contents/Resources/"

          echo "=== App bundle structure ==="
          find build/AgentSH.app -type f | sort

      - name: Sign app bundle (inside-out)
        env:
          SIGNING_IDENTITY: ${{ secrets.MACOS_SIGNING_IDENTITY }}
        run: |
          # 1. System Extension
          codesign --force --sign "$SIGNING_IDENTITY" \
            --entitlements macos/agentsh/SysExt.entitlements \
            --options runtime --timestamp \
            "build/AgentSH.app/Contents/Library/SystemExtensions/SysExt.systemextension"

          # 2. XPC Service
          codesign --force --sign "$SIGNING_IDENTITY" \
            --options runtime --timestamp \
            "build/AgentSH.app/Contents/XPCServices/xpc.xpc"

          # 3. Approval Dialog
          codesign --force --sign "$SIGNING_IDENTITY" \
            --entitlements macos/agentsh/approval-dialog/approval-dialog.entitlements \
            --options runtime --timestamp \
            "build/AgentSH.app/Contents/Resources/approval-dialog.app"

          # 4. Main app bundle
          codesign --force --sign "$SIGNING_IDENTITY" \
            --entitlements macos/agentsh/agentsh/agentsh.entitlements \
            --options runtime --timestamp \
            "build/AgentSH.app"

          # 5. Verify
          codesign --verify --deep --strict --verbose=2 "build/AgentSH.app"

      - name: Notarize app bundle
        env:
          APPLE_ID: ${{ secrets.MACOS_NOTARIZATION_APPLE_ID }}
          APPLE_PASSWORD: ${{ secrets.MACOS_NOTARIZATION_PASSWORD }}
          TEAM_ID: ${{ secrets.MACOS_NOTARIZATION_TEAM_ID }}
        run: |
          ditto -c -k --keepParent build/AgentSH.app build/AgentSH.zip
          xcrun notarytool submit build/AgentSH.zip \
            --apple-id "$APPLE_ID" \
            --password "$APPLE_PASSWORD" \
            --team-id "$TEAM_ID" \
            --wait --timeout 20m
          xcrun stapler staple build/AgentSH.app

      - name: Create DMG and upload to release
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ github.ref_name }}
        run: |
          # Create DMG
          hdiutil create -volname "AgentSH" \
            -srcfolder build/AgentSH.app \
            -ov -format UDZO \
            "build/AgentSH-${VERSION}.dmg"

          # Delete old darwin tarballs from release
          for arch in amd64 arm64; do
            ARCHIVE="agentsh_${VERSION#v}_darwin_${arch}.tar.gz"
            gh release delete-asset "$VERSION" "$ARCHIVE" \
              --repo "${{ github.repository }}" \
              --yes || true
          done

          # Upload DMG
          gh release upload "$VERSION" "build/AgentSH-${VERSION}.dmg" \
            --repo "${{ github.repository }}" \
            --clobber
```

**Step 2: Update update-checksums dependency**

Change line 232 from:
```yaml
    needs: [goreleaser, alpine-build, sign-macos]
```
to:
```yaml
    needs: [goreleaser, alpine-build, build-macos-app]
```

**Step 3: Verify the full workflow YAML is valid**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: No output (valid YAML)

**Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: replace macOS CLI signing with app bundle build in release workflow"
```

---

### Task 2: Delete the Old Enterprise Workflow

**Files:**
- Delete: `.github/workflows/macos-enterprise.yml`
- Delete: `macos/AgentSH-files/AgentSH.entitlements`

**Step 1: Delete stale files**

```bash
rm .github/workflows/macos-enterprise.yml
rm macos/AgentSH-files/AgentSH.entitlements
```

**Step 2: Commit**

```bash
git add -A .github/workflows/macos-enterprise.yml macos/AgentSH-files/AgentSH.entitlements
git commit -m "ci: remove disabled macOS enterprise workflow (merged into release.yml)"
```

---

### Task 3: Update Makefile Targets

**Files:**
- Modify: `Makefile:108-160` (macOS enterprise targets)

**Step 1: Update the macOS build targets**

Replace the macOS enterprise section (lines 108-160) with updated paths. Key changes:
- `macos/AgentSH.xcodeproj` → `macos/agentsh/agentsh.xcodeproj`
- Build all Swift targets via the `agentsh` scheme (builds SysExt, xpc, approval-dialog as deps)
- Remove separate `build-approval-dialog` swiftc target (now built by xcodebuild)
- Update entitlements paths in `sign-bundle`
- Product names: `SysExt.systemextension`, `xpc.xpc`, `approval-dialog.app`

```makefile
# =============================================================================
# macOS Enterprise Build (System Extension + Network Extension)
# NOTE: build-swift, assemble-bundle, and sign-bundle require macOS with Xcode
# =============================================================================

# Build Go binary for macOS (CGO disabled for cross-compilation)
build-macos-go:
	mkdir -p build/AgentSH.app/Contents/MacOS
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build $(LDFLAGS) -o build/AgentSH.app/Contents/MacOS/agentsh ./cmd/agentsh

# Build Swift components via Xcode (requires macOS with Xcode)
build-swift:
	xcodebuild \
		-project macos/agentsh/agentsh.xcodeproj \
		-scheme agentsh \
		-configuration Release \
		-derivedDataPath build/DerivedData \
		CODE_SIGN_IDENTITY="" \
		CODE_SIGNING_REQUIRED=NO \
		CODE_SIGNING_ALLOWED=NO

# Assemble app bundle
assemble-bundle: build-macos-go build-swift
	mkdir -p build/AgentSH.app/Contents/{Library/SystemExtensions,XPCServices,Resources}
	cp macos/AgentSH-files/Info.plist build/AgentSH.app/Contents/
	cp -R build/DerivedData/Build/Products/Release/SysExt.systemextension \
		build/AgentSH.app/Contents/Library/SystemExtensions/
	cp -R build/DerivedData/Build/Products/Release/xpc.xpc \
		build/AgentSH.app/Contents/XPCServices/
	cp -R build/DerivedData/Build/Products/Release/approval-dialog.app \
		build/AgentSH.app/Contents/Resources/

# Sign bundle (requires SIGNING_IDENTITY env var)
sign-bundle:
	codesign --force --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/agentsh/SysExt.entitlements \
		--options runtime --timestamp \
		build/AgentSH.app/Contents/Library/SystemExtensions/SysExt.systemextension
	codesign --force --sign "$(SIGNING_IDENTITY)" \
		--options runtime --timestamp \
		build/AgentSH.app/Contents/XPCServices/xpc.xpc
	codesign --force --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/agentsh/approval-dialog/approval-dialog.entitlements \
		--options runtime --timestamp \
		build/AgentSH.app/Contents/Resources/approval-dialog.app
	codesign --force --sign "$(SIGNING_IDENTITY)" \
		--entitlements macos/agentsh/agentsh/agentsh.entitlements \
		--options runtime --timestamp \
		build/AgentSH.app
	codesign --verify --deep --strict --verbose=2 build/AgentSH.app

# Full enterprise build
build-macos-enterprise: assemble-bundle sign-bundle
	@echo "Enterprise build complete: build/AgentSH.app"
```

**Step 2: Remove the old `build-approval-dialog` target**

Delete lines 31-68 (the `APPROVAL_DIALOG_SOURCES`, `APPROVAL_DIALOG_FRAMEWORKS`, and `build-approval-dialog` target that used raw `swiftc`). These are now built by xcodebuild via `build-swift`.

Also remove `build-approval-dialog` from the `.PHONY` line at the top (line 7).

**Step 3: Commit**

```bash
git add Makefile
git commit -m "build: update Makefile macOS targets for new Xcode project structure"
```

---

### Task 4: Verify the Build Locally

**Step 1: Clean and rebuild Swift targets**

Run:
```bash
cd /Users/eran/work/canyonroad/agentsh
make clean
make build-swift
```
Expected: xcodebuild succeeds, products in `build/DerivedData/Build/Products/Release/`

**Step 2: Verify build products exist**

Run:
```bash
ls build/DerivedData/Build/Products/Release/SysExt.systemextension
ls build/DerivedData/Build/Products/Release/xpc.xpc
ls build/DerivedData/Build/Products/Release/approval-dialog.app
```
Expected: All three products exist

**Step 3: Test assemble-bundle (unsigned)**

Run:
```bash
make assemble-bundle
find build/AgentSH.app -type f | sort
```
Expected: App bundle assembled with Go binary, system extension, XPC service, approval dialog, and Info.plist

**Step 4: Commit (if any fixes were needed)**

---

### Task 5: Validate Workflow YAML Syntax

**Step 1: Check YAML is valid**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```
Expected: No errors

**Step 2: Check no stale references remain**

Run:
```bash
grep -rn "macos/AgentSH.xcodeproj\|macos/SysExt/\|AgentSH/AgentSH.entitlements\|sign-macos" .github/workflows/ Makefile
```
Expected: No output (no stale references)

**Step 3: Final commit if needed**
