#!/bin/bash
# Smoke test: verify basic functionality

set -e

cd "$(dirname "$0")/.."
export PYTHONPATH="${PYTHONPATH:+$PYTHONPATH:}$(pwd)"

echo "Kernels Smoke Test"
echo "=================="

echo ""
echo "[1/7] Checking Python version..."
python3 --version

echo ""
echo "[2/7] Running minimal example..."
python3 examples/01_minimal_request.py

echo ""
echo "[3/7] Running tool execution example..."
python3 examples/02_tool_execution.py

echo ""
echo "[3b] Running the remaining examples..."
for example in examples/0{3,4,5,6,7,8,9}*.py examples/1{0,1}*.py; do
  echo "  $example"
  python3 "$example" >/tmp/shards_kernel-example.out
done

echo ""
echo "[4/7] Checking CLI help..."
python3 -m shards_kernel --help

echo ""
echo "[5/7] Checking CLI version..."
python3 -m shards_kernel --version

echo ""
echo "[6/7] Exercising thread-safe nonce registry..."
python3 - <<'PY'
from implementations.permits_threadsafe import ThreadSafeNonceRegistry

registry = ThreadSafeNonceRegistry(ttl_ms=100)
assert registry.check_and_record("n", "iss", "sub", "permit", 2, 1000)
assert registry.check_and_record("n", "iss", "sub", "permit", 2, 1001)
assert not registry.check_and_record("n", "iss", "sub", "permit", 2, 1002)
assert registry.cleanup(1205) == 1
print("Nonce registry stats:", registry.stats())
PY

echo ""
echo "[7/7] Exercising SQLite audit storage..."
python3 - <<'PY'
from pathlib import Path
from implementations.storage import SQLiteAuditStorage

db_path = Path(".tmp/smoke/audit.db")
if db_path.exists():
    db_path.unlink()

entry = {
    "ledger_seq": 1,
    "entry_hash": "h1",
    "prev_hash": "genesis",
    "ts_ms": 1,
    "request_id": "req-1",
    "actor": "smoke",
    "intent": "verify",
    "decision": "allow",
    "state_from": "requested",
    "state_to": "approved",
}

storage = SQLiteAuditStorage(str(db_path))
storage.append("kernel-smoke", entry)
print("Storage health:", storage.health())
assert storage.list_entries("kernel-smoke")[0]["request_id"] == "req-1"
PY

echo ""
echo "=================="
echo "Smoke test passed."
