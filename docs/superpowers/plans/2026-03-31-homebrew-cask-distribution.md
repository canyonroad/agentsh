# Homebrew Cask Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Distribute the macOS AgentSH.app via Homebrew Cask, auto-publishing on each stable release.

**Architecture:** A cask template in the main repo gets version/SHA256 substituted by a new release workflow job that pushes the generated formula to a separate tap repo. The GoReleaser cask config is removed.

**Tech Stack:** Homebrew Cask (Ruby), GitHub Actions, shell scripting

**Spec:** `docs/superpowers/specs/2026-03-31-homebrew-cask-distribution-design.md`

---

### Task 1: Create the Homebrew tap repository

**Prereq:** This is a manual GitHub step, not automatable from CI.

- [ ] **Step 1: Create the `canyonroad/homebrew-tap` repository on GitHub**

Go to https://github.com/organizations/canyonroad/repositories/new and create:
- Name: `homebrew-tap`
- Visibility: Public (required for `brew tap` to work)
- Initialize with a README

- [ ] **Step 2: Create a PAT for CI access**

Create a fine-grained PAT (or classic with `repo` scope) that has `contents: write` on `canyonroad/homebrew-tap`. Add it as a repository secret named `HOMEBREW_TAP_GITHUB_TOKEN` in `canyonroad/agentsh` Settings > Secrets and variables > Actions.

- [ ] **Step 3: Verify access**

```bash
# Test that the token works (replace with actual token for manual test)
git clone https://github.com/canyonroad/homebrew-tap.git /tmp/tap-test
cd /tmp/tap-test && git log --oneline -1
rm -rf /tmp/tap-test
```

---

### Task 2: Create the cask template

**Files:**
- Create: `scripts/homebrew-cask.rb.tmpl`

- [ ] **Step 1: Create the template file**

```ruby
cask "agentsh" do
  version "__VERSION__"
  sha256 "__SHA256__"

  url "https://github.com/canyonroad/agentsh/releases/download/v#{version}/AgentSH-v#{version}.dmg"
  name "AgentSH"
  desc "Secure sandboxed shell for AI agents"
  homepage "https://github.com/canyonroad/agentsh"

  depends_on macos: ">= :sonoma"

  app "AgentSH.app"

  uninstall quit:      "ai.canyonroad.agentsh",
            signal:    ["TERM", "agentsh"],
            launchctl: "ai.canyonroad.agentsh.daemon"

  zap trash: [
    "~/Library/Application Support/agentsh",
    "~/Library/Preferences/ai.canyonroad.agentsh.plist",
    "~/Library/Caches/ai.canyonroad.agentsh",
    "~/Library/LaunchAgents/ai.canyonroad.agentsh.daemon.plist",
  ]

  caveats <<~EOS
    After installation, open AgentSH.app to activate the system extension:
      open /Applications/AgentSH.app
    You will be prompted in System Settings to approve the extension.
  EOS
end
```

Write this to `scripts/homebrew-cask.rb.tmpl`.

- [ ] **Step 2: Verify the template has correct placeholders**

```bash
grep -c '__VERSION__\|__SHA256__' scripts/homebrew-cask.rb.tmpl
```

Expected: `2` (one of each)

- [ ] **Step 3: Commit**

```bash
git add scripts/homebrew-cask.rb.tmpl
git commit -m "feat: add Homebrew cask template for macOS distribution"
```

---

### Task 3: Remove the GoReleaser homebrew_casks section

**Files:**
- Modify: `.goreleaser.yml:306-346`

- [ ] **Step 1: Read the current homebrew_casks section**

Read `.goreleaser.yml` lines 300-350 to confirm the exact section boundaries.

- [ ] **Step 2: Replace the homebrew_casks section with a comment**

Remove lines 306-346 (the entire `homebrew_casks:` block) and replace with:

```yaml
# Homebrew cask is published by the publish-homebrew-cask job in release.yml
# (not managed by GoReleaser — the cask installs the signed DMG, not raw binaries)
```

- [ ] **Step 3: Verify GoReleaser config is still valid**

```bash
grep -n 'homebrew' .goreleaser.yml
```

Expected: Only the comment lines, no `homebrew_casks:` key.

- [ ] **Step 4: Commit**

```bash
git add .goreleaser.yml
git commit -m "chore: remove disabled GoReleaser homebrew_casks config

Homebrew cask publishing is now handled by the publish-homebrew-cask
job in release.yml, which publishes the signed DMG rather than raw
CLI binaries."
```

---

### Task 4: Add the publish-homebrew-cask job to release.yml

**Files:**
- Modify: `.github/workflows/release.yml` (insert new job after `update-checksums` at line 396, before `docker-test` at line 398)

- [ ] **Step 1: Read the current release.yml around the insertion point**

Read `.github/workflows/release.yml` lines 370-410 to confirm the exact location between `update-checksums` and `docker-test`.

- [ ] **Step 2: Insert the new job**

Add the following after the `update-checksums` job (after line 396) and before the `docker-test` job:

```yaml

  # Publish Homebrew cask to canyonroad/homebrew-tap (stable releases only).
  publish-homebrew-cask:
    runs-on: ubuntu-latest
    needs: [build-macos-app]
    if: "!contains(github.ref_name, '-')"
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@v4

      - name: Download DMG and compute SHA256
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          VERSION: ${{ github.ref_name }}
        run: |
          gh release download "$VERSION" \
            --pattern "AgentSH-*.dmg" \
            --repo "${{ github.repository }}" \
            --dir .
          DMG_FILE=$(ls AgentSH-*.dmg)
          if [ "$(echo "$DMG_FILE" | wc -l)" -ne 1 ]; then
            echo "::error::Expected exactly one DMG file, found: $DMG_FILE"
            exit 1
          fi
          SHA256=$(sha256sum "$DMG_FILE" | awk '{print $1}')
          echo "SHA256=$SHA256" >> "$GITHUB_ENV"
          echo "CLEAN_VERSION=${VERSION#v}" >> "$GITHUB_ENV"

      - name: Generate cask formula from template
        run: |
          sed -e "s/__VERSION__/$CLEAN_VERSION/g" \
              -e "s/__SHA256__/$SHA256/g" \
              scripts/homebrew-cask.rb.tmpl > agentsh.rb
          echo "--- Generated cask formula ---"
          cat agentsh.rb

      - name: Push to homebrew-tap
        env:
          TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_GITHUB_TOKEN }}
        run: |
          git clone "https://x-access-token:${TAP_TOKEN}@github.com/canyonroad/homebrew-tap.git" tap
          mkdir -p tap/Casks
          cp agentsh.rb tap/Casks/agentsh.rb
          cd tap
          git config user.name "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add Casks/agentsh.rb
          git diff --cached --quiet || git commit -m "Update agentsh cask to ${CLEAN_VERSION}"
          git push
```

- [ ] **Step 3: Verify YAML syntax**

```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"
```

Expected: No errors.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat: add publish-homebrew-cask job to release pipeline

Auto-publishes the Homebrew cask formula to canyonroad/homebrew-tap
on stable releases (tags without pre-release suffix). Downloads the
signed DMG, computes SHA256, generates the cask from template, and
pushes to the tap repo."
```

---

### Task 5: Test with a stable release

- [ ] **Step 1: Push changes to main**

```bash
git push origin main
```

- [ ] **Step 2: Tag a stable release to trigger the full pipeline**

```bash
git tag v0.16.11
git push origin v0.16.11
```

- [ ] **Step 3: Monitor the release build**

```bash
gh run list --limit 1 --json databaseId,headBranch --jq '.[0].databaseId'
# Then:
gh run watch <RUN_ID>
```

Wait for all jobs to complete, including `publish-homebrew-cask`.

- [ ] **Step 4: Verify the cask was pushed to the tap repo**

```bash
gh api repos/canyonroad/homebrew-tap/contents/Casks/agentsh.rb --jq '.content' | base64 -d
```

Verify the formula has the correct version and SHA256.

- [ ] **Step 5: Test the installation**

```bash
brew tap canyonroad/tap
brew install --cask agentsh
```

Verify:
- `AgentSH.app` is installed in `/Applications`
- The caveats message is displayed
- Opening the app triggers the system extension approval prompt

- [ ] **Step 6: Test uninstall**

```bash
brew uninstall --cask agentsh
```

Verify:
- `AgentSH.app` is removed from `/Applications`
- The launchd daemon is unloaded
