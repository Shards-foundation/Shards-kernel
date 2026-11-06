"""Additional edge-case tests for shared validation utilities."""

from shards_kernel.common.types import KernelRequest
from shards_kernel.common.validate import validate_request


def test_empty_request_fields_are_rejected():
    request = KernelRequest(
        request_id="", ts_ms=-1, actor="", intent="", params={}
    )
    errors = validate_request(request)
    assert "request_id is required" in errors
    assert "ts_ms must be non-negative" in errors
    assert "actor is required" in errors


def test_published_receipt_status_schemas_include_queued():
    """The public QUEUED status must remain documented across SDK and specs."""
    from pathlib import Path

    from shards_kernel.common.types import ReceiptStatus

    root = Path(__file__).resolve().parents[1]
    assert {x.value for x in ReceiptStatus} == {
        "ACCEPTED", "QUEUED", "REJECTED", "FAILED"
    }
    for relative_path, marker in (
        ("spec/SPEC.md", "| QUEUED"),
        ("docs/architecture/SCHEMAS.md", "ACCEPTED, QUEUED, REJECTED, FAILED"),
        ("docs/sdk/API.md", "ACCEPTED, QUEUED, REJECTED, FAILED"),
        ("spec/ERROR_MODEL.md", "Halt queued (in-flight tool)"),
        ("docs/operations/HTTP_API_AUTH.md", "receipt_status: QUEUED"),
    ):
        content = (root / relative_path).read_text(encoding="utf-8")
        assert marker in content, f"Queued halt contract missing from {relative_path}"
