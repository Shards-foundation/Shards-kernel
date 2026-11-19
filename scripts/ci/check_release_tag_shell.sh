#!/usr/bin/env bash
# Execute the exact GitHub Release tag resolver against real local Git refs.
# No network, GitHub credentials, or production tags are used.
set -euo pipefail
cd "$(dirname "$0")/../.."
root="$PWD"
release_tag="${RELEASE_TEST_TAG:-v0.1.3}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python - "$root/.github/workflows/publish-${release_tag}.yml" "$tmp/tag-resolver.sh" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
marker = "          release_tag_commit() {"
start = lines.index(marker)
body = []
for line in lines[start:]:
    if not line.startswith("          "):
        raise SystemExit("Release tag resolver block ended unexpectedly")
    body.append(line[10:])
    if line == "          }":
        break
if len(body) < 6 or body[-1] != "}":
    raise SystemExit("Release tag resolver is incomplete")
Path(sys.argv[2]).write_text("\n".join(body) + "\n", encoding="utf-8")
PY

bash -n "$tmp/tag-resolver.sh"
git init --bare --quiet "$tmp/origin.git"
git init --quiet "$tmp/work"
git -C "$tmp/work" config user.name "Release Check"
git -C "$tmp/work" config user.email "release-check@example.invalid"
git -C "$tmp/work" remote add origin "$tmp/origin.git"
git -C "$tmp/work" checkout -qb main
printf 'signed-off local test\n' > "$tmp/work/test.txt"
git -C "$tmp/work" add test.txt
git -C "$tmp/work" commit -qm "synthetic release test"
commit="$(git -C "$tmp/work" rev-parse HEAD)"
git -C "$tmp/work" push --quiet origin HEAD:refs/heads/main

cd "$tmp/work"
# shellcheck disable=SC1090
source "$tmp/tag-resolver.sh"

# An annotated tag's ref is a tag-object SHA, not the target commit SHA.
if [ "$release_tag" = "v0.1.3" ]; then
  git tag -a v0.1.3 -m "synthetic annotated release"
else
  git tag -a "$release_tag" -m "synthetic annotated release"
fi
git push --quiet origin "refs/tags/$release_tag"
tag_object="$(git ls-remote --tags --refs origin "refs/tags/$release_tag" | cut -f1)"
test "$tag_object" != "$commit"
test "$(release_tag_commit)" = "$commit" || {
  echo "Annotated tag failed to peel to the verified commit" >&2
  exit 1
}

# A lightweight tag has no peeled ^{} ref and must use the direct SHA.
git tag -d "$release_tag" >/dev/null
git --git-dir="$tmp/origin.git" update-ref -d "refs/tags/$release_tag"
git tag "$release_tag" "$commit"
git push --quiet origin "refs/tags/$release_tag"
test -z "$(git ls-remote --tags origin "refs/tags/${release_tag}^{}" | cut -f1)"
test "$(release_tag_commit)" = "$commit" || {
  echo "Lightweight tag failed to resolve to the verified commit" >&2
  exit 1
}

# Missing ref must yield an empty value, never an unrelated object.
git --git-dir="$tmp/origin.git" update-ref -d "refs/tags/$release_tag"
test -z "$(release_tag_commit)" || {
  echo "Missing tag unexpectedly resolved to a commit" >&2
  exit 1
}
echo "Release tag resolver: annotated, lightweight and absent: PASS"
