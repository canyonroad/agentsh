#!/usr/bin/env bash
set -euo pipefail

current_tag="${1:-${GITHUB_REF_NAME:-}}"
if [[ -z "$current_tag" ]]; then
  echo "usage: GITHUB_REF_NAME=<tag> $0" >&2
  exit 1
fi

emit() {
  local line="$1"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    printf '%s\n' "$line" >>"$GITHUB_ENV"
  else
    printf '%s\n' "$line"
  fi
}

emit "GORELEASER_CURRENT_TAG=$current_tag"

previous_tag="$(
  git tag --list 'v*' --sort=-version:refname |
    awk -v current="$current_tag" '
      $0 == current { seen = 1; next }
      !seen { next }
      { print; exit }
    '
)"

if [[ "$current_tag" != *-* ]]; then
  previous_tag="$(
    git tag --list 'v*' --sort=-version:refname |
      awk -v current="$current_tag" '
        $0 == current { seen = 1; next }
        !seen { next }
        $0 ~ /-/ { next }
        { print; exit }
      '
  )"
fi

if [[ -n "$previous_tag" ]]; then
  emit "GORELEASER_PREVIOUS_TAG=$previous_tag"
fi
