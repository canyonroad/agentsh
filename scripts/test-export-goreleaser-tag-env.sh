#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/export-goreleaser-tag-env.sh"

tmpdir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

cd "$tmpdir"
git init -q
git config user.name "Test User"
git config user.email "test@example.com"

commit_with_tag() {
  local tag="$1"
  local message="$2"
  printf '%s\n' "$message" > file.txt
  git add file.txt
  git commit -q -m "$message"
  git tag -a "$tag" -m "$tag"
}

commit_with_tag "v0.18.0" "v0.18.0"
commit_with_tag "v0.18.1" "v0.18.1"
commit_with_tag "v0.19.0-rc5" "v0.19.0-rc5"
commit_with_tag "v0.19.0-rc6" "v0.19.0-rc6"

printf 'v0.18.2 release candidate\n' > file.txt
git add file.txt
git commit -q -m "v0.18.2 candidate"
git tag -a "v0.18.2-rc1" -m "v0.18.2-rc1"
git tag -a "v0.18.2" -m "v0.18.2"

stable_output="$(GITHUB_REF_NAME=v0.18.2 "$helper")"
printf '%s\n' "$stable_output" | grep -qx 'GORELEASER_CURRENT_TAG=v0.18.2'
printf '%s\n' "$stable_output" | grep -qx 'GORELEASER_PREVIOUS_TAG=v0.18.1'

rc_output="$(GITHUB_REF_NAME=v0.19.0-rc6 "$helper")"
printf '%s\n' "$rc_output" | grep -qx 'GORELEASER_CURRENT_TAG=v0.19.0-rc6'
printf '%s\n' "$rc_output" | grep -qx 'GORELEASER_PREVIOUS_TAG=v0.19.0-rc5'

echo "PASS"
