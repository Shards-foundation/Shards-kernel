"""Security tests for SDK URL scheme validation."""

import unittest

from kernels.common.errors import KernelError
from kernels.sdk.client import KernelClient


class TestKernelClientURLValidation(unittest.TestCase):
    def test_accepts_http_and_https_urls(self) -> None:
        self.assertEqual(
            KernelClient("http://127.0.0.1:8080").config.base_url,
            "http://127.0.0.1:8080",
        )
        self.assertEqual(
            KernelClient("https://kernel.example.test/api").config.base_url,
            "https://kernel.example.test/api",
        )

    def test_rejects_non_http_schemes(self) -> None:
        for url in ("file:///etc/passwd", "ftp://example.test/resource", "javascript:alert(1)"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    KernelClient(url)

    def test_rejects_embedded_credentials_and_fragments(self) -> None:
        for url in (
            "http://user:password@localhost:8080",
            "https://kernel.example.test/api#fragment",
        ):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    KernelClient(url)

    def test_mutated_config_is_validated_before_request(self) -> None:
        client = KernelClient("http://127.0.0.1:8080")
        client.config.base_url = "file:///etc"
        with self.assertRaises(KernelError):
            client._make_request("GET", "/passwd")


if __name__ == "__main__":
    unittest.main()
