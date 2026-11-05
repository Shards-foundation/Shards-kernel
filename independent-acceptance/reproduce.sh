#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
RUN="$(mktemp -d)"
trap 'echo "Evidence workspace: $RUN"' EXIT
python3 -m venv "$RUN/.venv"
PY="$RUN/.venv/bin/python"
"$PY" -m pip install --upgrade pip
mkdir -p "$RUN/wheelhouse" "$RUN/evidence"
"$PY" -m pip download --no-deps --only-binary=:all: --dest "$RUN/wheelhouse" 'shards-kernel==0.1.2'
echo '08dc0df1ade8769a3c9cd7560fd22362e1a313aa78de5d1063c67d64a59fa057  '"$RUN"'/wheelhouse/shards_kernel-0.1.2-py3-none-any.whl' | sha256sum -c -
"$PY" -m pip install --no-cache-dir 'shards-kernel[crypto,mcp]==0.1.2'
"$PY" -m pip check
cp "$ROOT/run_acceptance.py" "$RUN/run_acceptance.py"
cd "$RUN"
export ACCEPTANCE_OUT="$RUN/evidence"
export ACCEPTANCE_WHEELHOUSE="$RUN/wheelhouse"
"$PY" -I "$RUN/run_acceptance.py"
find "$RUN/evidence" "$RUN/wheelhouse" -type f ! -name artifacts.sha256 -print0 | sort -z | xargs -0 sha256sum > "$RUN/evidence/artifacts.sha256"
cd "$ROOT"
cp -r "$RUN/evidence" "./evidence-output"
