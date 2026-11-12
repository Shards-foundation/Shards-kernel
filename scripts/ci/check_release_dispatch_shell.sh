#!/usr/bin/env bash
# Exercise the real workflow dispatch block without a network call or token.
set -euo pipefail
cd "$(dirname "$0")/../.."
release_tag="${RELEASE_TEST_TAG:-v0.1.3}"
workflow=".github/workflows/publish-${release_tag}.yml"
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

# Extract the actual YAML run block, rather than duplicating the invocation.
python - "$workflow" "$temp_dir/dispatch.sh" "$temp_dir/broken.sh" <<'PY'
from pathlib import Path
import sys

lines = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
marker = "      - name: Dispatch using trusted workflow run identity"
start = lines.index("        run: |", lines.index(marker)) + 1
commands = []
for line in lines[start:]:
    if line.startswith("          "):
        commands.append(line[10:])
    elif line.strip():
        break
script = "\n".join(commands) + "\n"
continuations = [line for line in commands if line.endswith(chr(92))]
if len(continuations) != 4 or any(line.endswith(chr(92) * 2) for line in continuations):
    raise SystemExit("Dispatch must have exactly four single Bash continuations")
Path(sys.argv[2]).write_text(script, encoding="utf-8")
original = "gh workflow run publish.yml " + chr(92) + "\n"
broken = "gh workflow run publish.yml " + chr(92) * 2 + "\n"
if original not in script:
    raise SystemExit("Cannot build regression-negative dispatch fixture")
Path(sys.argv[3]).write_text(script.replace(original, broken, 1), encoding="utf-8")
PY

# A mock gh binary records all arguments. No GitHub credentials are required.
cat > "$temp_dir/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$GH_ARGS_PATH"
SH
chmod 700 "$temp_dir/gh"

export PATH="$temp_dir:$PATH"
export GITHUB_REPOSITORY="Shards-foundation/Shards-kernel"
export GITHUB_RUN_ID="987654321"
export GH_ARGS_PATH="$temp_dir/gh-arguments"
bash -e -o pipefail "$temp_dir/dispatch.sh"

python - "$GH_ARGS_PATH" "$release_tag" <<'PY'
from pathlib import Path
import sys

actual = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
release_tag = sys.argv[2]
expected = [
    "workflow", "run", "publish.yml",
    "--repo", "Shards-foundation/Shards-kernel",
    "--ref", release_tag,
    "--field", f"release_tag={release_tag}",
    "--field", "verified_run_id=987654321",
]
if actual != expected:
    raise SystemExit(f"Incorrect gh workflow dispatch argv: {actual!r}")
print("Exact real Bash dispatch arguments: PASS")
PY

# Deliberately reintroduce the previous defect and prove it fails closed.
if bash -e -o pipefail "$temp_dir/broken.sh" >"$temp_dir/broken.log" 2>&1; then
  echo "Broken double-backslash dispatch unexpectedly succeeded" >&2
  exit 1
fi
grep -F -- "--repo: command not found" "$temp_dir/broken.log" >/dev/null || {
  echo "Broken dispatch did not fail for the expected reason" >&2
  cat "$temp_dir/broken.log" >&2
  exit 1
}
echo "Double-backslash regression fixture: PASS"
