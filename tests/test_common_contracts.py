"""Additional edge-case tests for shared validation utilities."""

from kernels.common.types import KernelRequest
from kernels.common.validate import validate_request


def test_empty_request_fields_are_rejected():
    request = KernelRequest(
        request_id="", ts_ms=-1, actor="", intent="", params={}
    )
    errors = validate_request(request)
    assert "request_id is required" in errors
    assert "ts_ms must be non-negative" in errors
    assert "actor is required" in errors
