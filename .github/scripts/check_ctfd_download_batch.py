"""Offline CTFd attachment durability and fsync batching regressions."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.ctfd import CTFdClient, CTFdError, Response


CHUNK = 64 * 1024
BATCH = 4 * 1024 * 1024
SCOPE = ("job", "owner", "workspace", "challenge")


class Budget:
    def __init__(self, root: Path):
        self.data_dir = root
        self.reservations = []
        self.commits = []
        self.unreserved = []
        self.releases = []

    def reserve(self, key, kind, owner, workspace, challenge, amount):
        self.reservations.append(amount)

    def release(self, key):
        self.releases.append(key)

    def commit_reserved_write(self, key, amount, writer):
        self.commits.append(amount)
        writer()

    def write_unreserved(self, amount, writer):
        self.unreserved.append(amount)
        writer()


def client_with_stream(payload: bytes, *, status=200, start=0, etag='"v1"',
                       interrupt_after=None):
    client = CTFdClient("https://ctfd.example")

    def request(url, maximum, *, sink, on_headers, **kwargs):
        headers = {"etag": etag}
        if status == 206:
            headers["content-range"] = f"bytes {start}-{len(payload) - 1}/{len(payload)}"
        else:
            headers["content-length"] = str(len(payload))
        on_headers(status, headers)
        sent = 0
        for position in range(start, len(payload), CHUNK):
            block = payload[position:position + CHUNK]
            sink(block)
            sent += len(block)
            if interrupt_after is not None and sent >= interrupt_after:
                raise CTFdError("simulated network interruption", received_bytes=sent)
        return Response(status, headers, b"", (), sent), url

    client._request = request
    return client


class DownloadBatchTests(unittest.TestCase):
    def test_large_known_length_batches_durable_writes(self):
        payload = bytes(range(256)) * (2 * BATCH // 256)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = Budget(root)
            client = client_with_stream(payload)
            with patch("ctf_agent.ctfd.os.fsync") as sync:
                result = client.download_to(
                    "https://ctfd.example/file", root / "part", storage_budget=budget,
                    storage_reservation=SCOPE,
                )
            self.assertEqual((root / "part").read_bytes(), payload)
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(result["bytes"], len(payload))
            self.assertEqual(budget.commits, [BATCH, BATCH])
            # Before batching, 128 network chunks caused 128 write fsyncs.
            # A fresh 200 response also fsyncs its truncate before writing.
            self.assertEqual(sync.call_count, 3)

    def test_interrupted_transfer_resumes_from_durable_prefix(self):
        payload = b"a" * BATCH + b"b" * (2 * CHUNK)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = Budget(root)
            first = client_with_stream(payload, interrupt_after=BATCH + CHUNK)
            with self.assertRaisesRegex(CTFdError, "simulated network interruption"):
                first.download_to("https://ctfd.example/file", root / "part",
                                  storage_budget=budget, storage_reservation=SCOPE)
            self.assertEqual((root / "part").stat().st_size, BATCH)
            self.assertEqual(budget.commits, [BATCH])

            resumed = client_with_stream(payload, status=206, start=BATCH)
            result = resumed.download_to("https://ctfd.example/file", root / "part",
                                         validator='etag:"v1"', storage_budget=budget,
                                         storage_reservation=SCOPE)
            self.assertEqual((root / "part").read_bytes(), payload)
            self.assertEqual(result["bytes"], len(payload))
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(budget.commits, [BATCH, 2 * CHUNK])

    def test_unknown_length_uses_one_unreserved_durable_write(self):
        payload = b"z" * (3 * CHUNK)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            budget = Budget(root)
            client = client_with_stream(payload)

            original = client._request

            def no_length(url, maximum, *, sink, on_headers, **kwargs):
                def headers(status, values):
                    values.pop("content-length", None)
                    on_headers(status, values)
                return original(url, maximum, sink=sink, on_headers=headers, **kwargs)

            client._request = no_length
            result = client.download_to("https://ctfd.example/file", root / "part",
                                        storage_budget=budget, storage_reservation=SCOPE)
            self.assertEqual(result["bytes"], len(payload))
            self.assertEqual(budget.releases, ["job"])
            self.assertEqual(budget.unreserved, [len(payload)])
            self.assertEqual(budget.commits, [])

    def test_without_budget_still_hashes_and_syncs_download(self):
        payload = b"unreserved-test" * 12000
        with tempfile.TemporaryDirectory() as directory:
            partial = Path(directory) / "part"
            with patch("ctf_agent.ctfd.os.fsync") as sync:
                result = client_with_stream(payload).download_to(
                    "https://ctfd.example/file", partial
                )
            self.assertEqual(partial.read_bytes(), payload)
            self.assertEqual(result["sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(sync.call_count, 2)

    def test_range_rejection_restarts_without_old_pending_bytes(self):
        old = b"old" * CHUNK
        replacement = b"replacement" * (CHUNK // 11)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            partial = root / "part"
            partial.write_bytes(old)
            budget = Budget(root)
            client = client_with_stream(replacement)
            full_request = client._request
            calls = []

            def reject_range(url, maximum, **kwargs):
                calls.append(kwargs.get("extra_headers", {}))
                if len(calls) == 1:
                    raise CTFdError("The remote server returned HTTP 416.")
                return full_request(url, maximum, **kwargs)

            client._request = reject_range
            result = client.download_to("https://ctfd.example/file", partial,
                                        validator='etag:"old"', storage_budget=budget,
                                        storage_reservation=SCOPE)
            self.assertEqual(partial.read_bytes(), replacement)
            self.assertEqual(result["sha256"], hashlib.sha256(replacement).hexdigest())
            self.assertEqual(result["bytes"], len(replacement))
            self.assertIn("Range", calls[0])
            self.assertFalse(calls[1])


if __name__ == "__main__":
    unittest.main()
