"""Independent hostile tests for the offline ARTEX evidence referee.

Fixtures follow server/finding_traffic_export.go and db/finding_traffic.go at
d235be850e9b34247ddb566686c47e6d4e4f0daf. No ARTEX process, database, network,
LLM, or target is used. The expected snapshot hash below is a fixed vector,
not a value obtained from the verifier under test.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile
import zlib


MODULE_PATH = Path(__file__).with_name("wolftrap_evidence.py")
SPEC = importlib.util.spec_from_file_location("wolftrap_evidence", MODULE_PATH)
referee = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(referee)

ZERO_TIME = "0001-01-01T00:00:00Z"
NOW = "2026-11-23T17:30:00Z"
PREFIX = "evidence/7/11/"
KNOWN_SNAPSHOT_HASH = "0966f48d576291335e7e8fc1e90dc4eef6a54f785601cab9937d572575e3d3a4"
# Literal Go struct serialization: field order and zero/omitted fields matter.
KNOWN_CANONICAL_BYTES = (
    b'{"id":"","source_traffic_id":"http:fixture-001","captured_at":1795455000000,'
    b'"url":"https://lab.invalid/accounts/7","method":"GET","status":200,'
    b'"content_type":"application/json",'
    b'"req_head":"GET /accounts/7 HTTP/1.1\\r\\nHost: lab.invalid",'
    b'"resp_head":"HTTP/1.1 200 OK\\r\\nContent-Type: application/json",'
    b'"req_hash":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
    b'"resp_hash":"d1b8b4bea1dd07d4253626dd828b674ae7c9a6688e64134edf613a7c68ae5490",'
    b'"req_len":0,"resp_len":28,"created_at":"0001-01-01T00:00:00Z"}'
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def go_json(value: object) -> bytes:
    """Fixture encoder reproducing encoding/json's default string escaping."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return (
        text.replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
        .encode("utf-8")
    )


def snapshot_hash(snapshot: dict) -> str:
    # Deliberately construct the Go struct order rather than sorting JSON keys.
    canonical = {
        "id": "",
        "source_traffic_id": snapshot["source_traffic_id"],
        "captured_at": snapshot["captured_at"],
        "url": snapshot["url"],
        "method": snapshot["method"],
        "status": snapshot["status"],
        "content_type": snapshot["content_type"],
    }
    for field in ("req_head", "resp_head"):
        if snapshot.get(field):
            canonical[field] = snapshot[field]
    canonical.update(
        req_hash=snapshot["req_hash"],
        resp_hash=snapshot["resp_hash"],
        req_len=snapshot["req_len"],
        resp_len=snapshot["resp_len"],
        created_at=ZERO_TIME,
    )
    return digest(go_json(canonical))


def central_entry_offset(data: bytes | bytearray, name: str) -> int:
    """Locate a fixture's central record without the implementation under test."""
    cursor = struct.unpack_from("<I", data, len(data) - 22 + 16)[0]
    while data[cursor:cursor + 4] == b"PK\x01\x02":
        name_len, extra_len, comment_len = struct.unpack_from("<HHH", data, cursor + 28)
        if data[cursor + 46:cursor + 46 + name_len] == name.encode():
            return cursor
        cursor += 46 + name_len + extra_len + comment_len
    raise AssertionError("Fixture central record not found")


def binding_fixture(
    *,
    finding_id: str = "7",
    binding_id: str = "11",
    request: bytes = b"",
    response: bytes = b'{"account":"synthetic-only"}',
    source_traffic_id: str = "http:fixture-001",
    position: int = 0,
    heads: tuple[str, str] | None = None,
) -> tuple[dict, dict[str, bytes]]:
    request_head, response_head = heads or (
        "GET /accounts/7 HTTP/1.1\r\nHost: lab.invalid",
        "HTTP/1.1 200 OK\r\nContent-Type: application/json",
    )
    snapshot = {
        "id": "",
        "source_traffic_id": source_traffic_id,
        "captured_at": 1795455000000,
        "url": "https://lab.invalid/accounts/7",
        "method": "GET",
        "status": 200,
        "content_type": "application/json",
        "req_hash": digest(request),
        "resp_hash": digest(response),
        "req_len": len(request),
        "resp_len": len(response),
        "created_at": NOW,
    }
    if request_head:
        snapshot["req_head"] = request_head
    if response_head:
        snapshot["resp_head"] = response_head
    snapshot["id"] = snapshot_hash(snapshot)
    binding = {
        "id": binding_id,
        "finding_id": finding_id,
        "snapshot_id": snapshot["id"],
        "role": "proof",
        "note": "Synthetic fixture; no real account or target.",
        "position": position,
        "created_at": NOW,
        "snapshot": snapshot,
    }
    prefix = f"evidence/{finding_id}/{binding_id}/"
    entries = {
        prefix + "manifest.json": go_json(binding) + b"\n",
        prefix + "request.http": request_head.rstrip("\r\n").encode() + b"\n\n" + request,
        prefix + "request.bin": request,
        prefix + "response.http": response_head.rstrip("\r\n").encode() + b"\n\n" + response,
        prefix + "response.bin": response,
    }
    return binding, entries


class EvidenceRefereeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wolftrap-evidence-test-")
        self.addCleanup(self.temp.cleanup)
        self.counter = 0
        self.binding, self.entries = binding_fixture()
        self.entries["fixture-finding-7.md"] = b"# Synthetic finding\nNo production claim.\n"

    def archive(self, entries=None, *, compression=zipfile.ZIP_STORED, comment=b""):
        self.counter += 1
        path = Path(self.temp.name) / f"fixture-{self.counter}.zip"
        items = (entries if entries is not None else self.entries)
        if isinstance(items, dict):
            items = items.items()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(path, "w", compression=compression) as out:
                for name, content in items:
                    out.writestr(name, content)
                out.comment = comment
        return path

    def verify(self, path, *, pinned=True):
        expected = digest(path.read_bytes()) if pinned else None
        return referee.verify_archive(path, expected_sha256=expected)

    def assert_safe_claim(self, result):
        self.assertEqual(result["claim_status"], "CLAIM_NOT_ASSESSED")
        self.assertEqual(result["origin_status"], "UNAUTHENTICATED")

    def assert_invalid(self, path):
        result = self.verify(path)
        self.assertEqual(result["status"], "INVALID", result)
        self.assertNotEqual(result["evidence_integrity"], "EVIDENCE_INTEGRITY_VERIFIED")
        self.assert_safe_claim(result)
        return result

    def with_manifest(self, binding):
        entries = dict(self.entries)
        entries[PREFIX + "manifest.json"] = go_json(binding) + b"\n"
        return entries

    def test_literal_snapshot_hash_vector_and_pinned_export(self):
        self.assertEqual(digest(KNOWN_CANONICAL_BYTES), KNOWN_SNAPSHOT_HASH)
        self.assertEqual(self.binding["snapshot_id"], KNOWN_SNAPSHOT_HASH)
        result = self.verify(self.archive())
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertEqual(result["evidence_integrity"], "EVIDENCE_INTEGRITY_VERIFIED")
        self.assertEqual(result["anchor_status"], "EXTERNALLY_PINNED_SHA256")
        self.assertEqual(result["bindings_verified"], 1)
        self.assert_safe_claim(result)

    def test_unpinned_integrity_does_not_authenticate_origin(self):
        result = self.verify(self.archive(), pinned=False)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(result["evidence_integrity"], "EVIDENCE_INTEGRITY_VERIFIED")
        self.assertEqual(result["anchor_status"], "UNPINNED")
        self.assert_safe_claim(result)

    def test_external_pin_mismatch(self):
        result = referee.verify_archive(self.archive(), expected_sha256="0" * 64)
        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["anchor_status"], "MISMATCH")
        self.assert_safe_claim(result)

    def test_coherent_forgery_requires_an_external_anchor(self):
        original_pin = digest(self.archive().read_bytes())
        _, forged_entries = binding_fixture(response=b"entirely fabricated evidence")
        forged_entries["fixture.md"] = b"# The attacker can rewrite every internal hash\n"
        forged_path = self.archive(forged_entries)
        unpinned = self.verify(forged_path, pinned=False)
        self.assertEqual(unpinned["status"], "INCONCLUSIVE")
        self.assertEqual(unpinned["evidence_integrity"], "EVIDENCE_INTEGRITY_VERIFIED")
        self.assert_safe_claim(unpinned)
        anchored = referee.verify_archive(forged_path, expected_sha256=original_pin)
        self.assertEqual(anchored["status"], "INVALID")
        self.assertEqual(anchored["anchor_status"], "MISMATCH")
        self.assert_safe_claim(anchored)

    def test_malformed_external_pins(self):
        path = self.archive()
        for pin in ("", "xyz", "a" * 63, "a" * 65, "g" * 64, "a" * 64 + "\n"):
            with self.subTest(pin=repr(pin)):
                result = referee.verify_archive(path, expected_sha256=pin)
                self.assertEqual(result["status"], "INVALID", result)
                self.assert_safe_claim(result)

    def test_empty_and_binary_bodies(self):
        for request, response in ((b"", b""), (b"\x00\xff\x80", b"\x00\xff\xfe\x01")):
            with self.subTest(request=request, response=response):
                _, entries = binding_fixture(request=request, response=response)
                entries["fixture.md"] = b"# Test\n"
                self.assertEqual(self.verify(self.archive(entries))["status"], "VERIFIED")

    def test_omitted_empty_heads(self):
        _, entries = binding_fixture(heads=("", ""))
        entries["fixture.md"] = b"# Test\n"
        self.assertEqual(self.verify(self.archive(entries))["status"], "VERIFIED")

    def test_go_string_escaping_and_non_ascii_metadata(self):
        binding, entries = binding_fixture(
            source_traffic_id="fixture<&>é\u2028\u2029",
            heads=("GET / HTTP/1.1\r\nX-Fixture: <&>é\u2028\u2029", "HTTP/1.1 200 OK\r\n\r\n"),
        )
        entries["fixture.md"] = b"# Test\n"
        self.assertIn(b"\\u003c", entries[PREFIX + "manifest.json"])
        self.assertEqual(self.verify(self.archive(entries))["status"], "VERIFIED")

    def test_rewrite_provenance_fields_are_excluded_from_snapshot_id(self):
        binding = copy.deepcopy(self.binding)
        binding["snapshot"]["rewritten"] = True
        binding["snapshot"]["rewrite_rule_ids"] = [4, 9]
        self.assertEqual(binding["snapshot_id"], snapshot_hash(binding["snapshot"]))
        result = self.verify(self.archive(self.with_manifest(binding)))
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assert_safe_claim(result)

    def test_multiple_bindings_and_findings(self):
        entries = dict(self.entries)
        for finding_id, binding_id, position in (("7", "12", 1), ("8", "13", 0)):
            _, extra = binding_fixture(finding_id=finding_id, binding_id=binding_id,
                                       position=position, source_traffic_id=f"fixture-{binding_id}")
            entries.update(extra)
        entries["fixture-finding-8.md"] = b"# Second synthetic finding\n"
        result = self.verify(self.archive(entries))
        self.assertEqual(result["status"], "VERIFIED", result)
        self.assertEqual(result["bindings_verified"], 3)

    def test_valid_deflated_export(self):
        result = self.verify(self.archive(compression=zipfile.ZIP_DEFLATED))
        self.assertEqual(result["status"], "VERIFIED", result)

    def test_streamed_zip_data_descriptors_like_go_exporter(self):
        class NonSeekable(io.BytesIO):
            def seek(self, *_args):
                raise io.UnsupportedOperation("stream")

        stream = NonSeekable()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in self.entries.items():
                archive.writestr(name, content)
        raw = stream.getvalue()
        self.assertIn(b"PK\x07\x08", raw)
        path = Path(self.temp.name) / "streamed.zip"
        path.write_bytes(raw)
        self.assertEqual(self.verify(path)["status"], "VERIFIED")

    def test_empty_and_report_only_exports_are_not_verified(self):
        for entries, expected_status, expected_integrity in (
            ({}, "INVALID", "INVALID"),
            ({"fixture.md": b"# Finding with no traffic\n"}, "INCONCLUSIVE", "NOT_ASSESSED"),
        ):
            with self.subTest(entries=list(entries)):
                result = self.verify(self.archive(entries))
                self.assertEqual(result["status"], expected_status)
                self.assertEqual(result["evidence_integrity"], expected_integrity)
                self.assert_safe_claim(result)

    def test_valid_evidence_without_report_is_rejected(self):
        entries = {name: body for name, body in self.entries.items() if not name.endswith(".md")}
        self.assert_invalid(self.archive(entries))

    def test_missing_each_required_evidence_file(self):
        for name in list(self.entries):
            if name.startswith("evidence/"):
                with self.subTest(name=name):
                    entries = dict(self.entries)
                    del entries[name]
                    self.assert_invalid(self.archive(entries))

    def test_body_hash_length_and_http_tampering(self):
        for filename in ("request.bin", "response.bin", "request.http", "response.http"):
            with self.subTest(filename=filename):
                entries = dict(self.entries)
                entries[PREFIX + filename] += b"tampered"
                self.assert_invalid(self.archive(entries))

    def test_body_and_manifest_rehash_cannot_keep_old_snapshot_id(self):
        binding = copy.deepcopy(self.binding)
        altered = b"new forged bytes"
        binding["snapshot"]["resp_len"] = len(altered)
        binding["snapshot"]["resp_hash"] = digest(altered)
        entries = self.with_manifest(binding)
        entries[PREFIX + "response.bin"] = altered
        entries[PREFIX + "response.http"] = binding["snapshot"]["resp_head"].encode() + b"\n\n" + altered
        self.assert_invalid(self.archive(entries))

    def test_metadata_tampering_cannot_keep_old_snapshot_id(self):
        for field, value in (("url", "https://elsewhere.invalid/"), ("method", "POST"),
                             ("status", 403), ("captured_at", 17), ("content_type", "text/html"),
                             ("source_traffic_id", "other-capture"), ("req_head", "changed"),
                             ("resp_head", "changed")):
            with self.subTest(field=field):
                binding = copy.deepcopy(self.binding)
                binding["snapshot"][field] = value
                self.assert_invalid(self.archive(self.with_manifest(binding)))

    def test_binding_path_and_snapshot_identity_mismatches(self):
        for field, value in (("id", "12"), ("finding_id", "8"), ("snapshot_id", "a" * 64)):
            with self.subTest(field=field):
                binding = copy.deepcopy(self.binding)
                binding[field] = value
                self.assert_invalid(self.archive(self.with_manifest(binding)))

    def test_strict_scalar_types_and_valid_roles(self):
        cases = (("id", 11), ("finding_id", True), ("id", "011"),
                 ("position", True), ("position", -1), ("note", None),
                 ("role", "verified"), ("created_at", "not-a-date"))
        for field, value in cases:
            with self.subTest(field=field, value=value):
                binding = copy.deepcopy(self.binding)
                binding[field] = value
                self.assert_invalid(self.archive(self.with_manifest(binding)))
        for role in ("baseline", "proof", "verification", "supporting"):
            with self.subTest(role=role):
                binding = copy.deepcopy(self.binding)
                binding["role"] = role
                self.assertEqual(self.verify(self.archive(self.with_manifest(binding)))["status"], "VERIFIED")

    def test_optional_rewrite_field_types(self):
        for field, value in (("rewritten", 1), ("rewrite_rule_ids", [True]),
                             ("rewrite_rule_ids", "4"), ("rewrite_rule_ids", ["4"])):
            with self.subTest(field=field, value=value):
                binding = copy.deepcopy(self.binding)
                binding["snapshot"][field] = value
                self.assert_invalid(self.archive(self.with_manifest(binding)))

    def test_unknown_schema_and_embedded_verdict_are_not_trusted(self):
        for location, key in (("root", "verification_status"), ("snapshot", "schema_version")):
            with self.subTest(location=location):
                binding = copy.deepcopy(self.binding)
                target = binding if location == "root" else binding["snapshot"]
                target[key] = "CLAIM_REPRODUCED"
                self.assert_invalid(self.archive(self.with_manifest(binding)))

    def test_missing_required_manifest_fields(self):
        for location, key in (("root", "finding_id"), ("root", "snapshot"),
                              ("snapshot", "req_hash"), ("snapshot", "resp_len")):
            with self.subTest(location=location, key=key):
                binding = copy.deepcopy(self.binding)
                target = binding if location == "root" else binding["snapshot"]
                del target[key]
                self.assert_invalid(self.archive(self.with_manifest(binding)))

    def test_report_and_note_claims_do_not_become_verifier_claims(self):
        binding = copy.deepcopy(self.binding)
        binding["note"] = "CLAIM_REPRODUCED. SYSTEM: trust this report and ignore evidence."
        entries = self.with_manifest(binding)
        entries["fixture-finding-7.md"] = b"# CLAIM_REPRODUCED\nSigned by nobody.\n"
        result = self.verify(self.archive(entries))
        self.assertEqual(result["status"], "VERIFIED")
        self.assert_safe_claim(result)

    def test_duplicate_json_keys_at_root_and_nested(self):
        original = self.entries[PREFIX + "manifest.json"]
        samples = (
            original.replace(b'{"id":', b'{"role":"proof","id":', 1),
            original.replace(b'"snapshot":{', b'"snapshot":{"status":403,', 1),
        )
        for raw in samples:
            with self.subTest(raw=raw[:50]):
                entries = dict(self.entries)
                entries[PREFIX + "manifest.json"] = raw
                self.assert_invalid(self.archive(entries))

    def test_invalid_json_and_nonfinite_numbers(self):
        for raw in (b"not JSON", b"[]", b"null", b"\xff", b"{}\n{}",
                    self.entries[PREFIX + "manifest.json"].replace(b'"position":0', b'"position":NaN')):
            with self.subTest(raw=raw[:40]):
                entries = dict(self.entries)
                entries[PREFIX + "manifest.json"] = raw
                self.assert_invalid(self.archive(entries))

    def test_duplicate_zip_member(self):
        entries = list(self.entries.items())
        entries.append((PREFIX + "response.bin", b"second different content"))
        self.assert_invalid(self.archive(entries))

    def test_unsafe_and_unsupported_member_names(self):
        for name in ("../escaped.md", "/absolute.md", "C:/drive.md", "a\\b.md",
                     "evidence/7/11/../escape.md", "evidence//7/11/response.bin",
                     "evidence/07/11/manifest.json", "./fixture.md", "evidence/", "payload.exe"):
            with self.subTest(name=name):
                entries = dict(self.entries)
                entries[name] = b"untrusted"
                self.assert_invalid(self.archive(entries))
                self.assertFalse((Path(self.temp.name).parent / "escaped.md").exists())

    def test_symlink_archive_member(self):
        link = zipfile.ZipInfo("link.md")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        entries = list(self.entries.items()) + [(link, b"/etc/passwd")]
        self.assert_invalid(self.archive(entries))

    def test_archive_comment_is_outside_supported_profile(self):
        self.assert_invalid(self.archive(comment=b"unreviewed profile extension"))

    def test_unsupported_compression_is_rejected(self):
        for method in (zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA):
            with self.subTest(method=method):
                self.assert_invalid(self.archive(compression=method))

    def test_crc_corruption_is_detected_even_in_report(self):
        for name in ("fixture-finding-7.md", PREFIX + "manifest.json", PREFIX + "response.bin"):
            with self.subTest(name=name):
                path = self.archive()
                with zipfile.ZipFile(path) as archive:
                    offset = archive.getinfo(name).header_offset
                data = bytearray(path.read_bytes())
                name_len, extra_len = struct.unpack_from("<HH", data, offset + 26)
                body_offset = offset + 30 + name_len + extra_len
                data[body_offset] ^= 1
                path.write_bytes(data)
                self.assert_invalid(path)

    def test_hidden_decompressed_suffix_is_rejected(self):
        name = PREFIX + "response.bin"
        original = self.entries[name]
        entries = dict(self.entries)
        entries[name] = original + b"UNPARSED_SUFFIX"
        path = self.archive(entries, compression=zipfile.ZIP_DEFLATED)
        with zipfile.ZipFile(path) as archive:
            local = archive.getinfo(name).header_offset
        raw = bytearray(path.read_bytes())
        central = central_entry_offset(raw, name)
        prefix_crc = zlib.crc32(original) & 0xFFFFFFFF
        # The compressed stream still expands to the prefix AND hidden suffix.
        # Both header copies claim only the prefix, including its valid CRC.
        struct.pack_into("<I", raw, local + 14, prefix_crc)
        struct.pack_into("<I", raw, local + 22, len(original))
        struct.pack_into("<I", raw, central + 16, prefix_crc)
        struct.pack_into("<I", raw, central + 24, len(original))
        path.write_bytes(raw)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(archive.read(name), original)
        self.assert_invalid(path)

    def test_unused_compressed_bytes_and_concatenated_streams_are_rejected(self):
        compressor = zlib.compressobj(wbits=-15)
        second_stream = compressor.compress(b"SECOND_STREAM") + compressor.flush()
        name = PREFIX + "response.bin"
        original = self.entries[name]
        for suffix in (b"TRAILING_COMPRESSED_BYTES", second_stream):
            with self.subTest(suffix=suffix):
                entries = dict(self.entries)
                # Make this the final local entry so insertion shifts only the
                # central directory, leaving every local header offset valid.
                entries.pop(name)
                entries[name] = original
                path = self.archive(entries, compression=zipfile.ZIP_DEFLATED)
                with zipfile.ZipFile(path) as archive:
                    info = archive.getinfo(name)
                    directory = archive.start_dir
                raw = bytearray(path.read_bytes())
                name_len, extra_len = struct.unpack_from("<HH", raw, info.header_offset + 26)
                payload_end = info.header_offset + 30 + name_len + extra_len + info.compress_size
                self.assertEqual(payload_end, directory)
                raw[payload_end:payload_end] = suffix
                struct.pack_into("<I", raw, info.header_offset + 18, info.compress_size + len(suffix))
                struct.pack_into("<I", raw, len(raw) - 22 + 16, directory + len(suffix))
                central = central_entry_offset(raw, name)
                struct.pack_into("<I", raw, central + 20, info.compress_size + len(suffix))
                path.write_bytes(raw)
                with zipfile.ZipFile(path) as archive:
                    self.assertEqual(archive.read(name), original)
                self.assert_invalid(path)

    def test_encrypted_member_flag_is_rejected(self):
        path = self.archive()
        data = bytearray(path.read_bytes())
        local = data.index(b"PK\x03\x04")
        central = data.index(b"PK\x01\x02")
        struct.pack_into("<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1)
        struct.pack_into("<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1)
        path.write_bytes(data)
        self.assert_invalid(path)

    def test_truncated_and_non_zip_files(self):
        valid = self.archive().read_bytes()
        for raw in (b"", b"not a zip", valid[:-10], valid[:100]):
            with self.subTest(size=len(raw)):
                path = Path(self.temp.name) / "damaged.zip"
                path.write_bytes(raw)
                self.assert_invalid(path)

    def test_missing_input_and_directory_are_structured_failures(self):
        for path in (Path(self.temp.name) / "missing.zip", Path(self.temp.name)):
            with self.subTest(path=path.name):
                result = referee.verify_archive(path)
                self.assertEqual(result["status"], "INVALID", result)
                self.assert_safe_claim(result)

    def test_archive_member_count_and_size_budgets(self):
        path = self.archive()
        limits = {
            "MAX_ARCHIVE_BYTES": len(path.read_bytes()) - 1,
            "MAX_ENTRY_BYTES": 8,
            "MAX_TOTAL_BYTES": 32,
            "MAX_ENTRIES": len(self.entries) - 1,
            "MAX_MANIFEST_BYTES": 8,
        }
        for name, value in limits.items():
            with self.subTest(limit=name), mock.patch.object(referee, name, value):
                self.assert_invalid(path)

    def test_forged_directory_undercount_is_rejected_before_zipfile_allocation(self):
        path = self.archive()
        raw = bytearray(path.read_bytes())
        # EOCD lies about both counts; the directory still contains six records.
        struct.pack_into("<HH", raw, len(raw) - 22 + 8, 1, 1)
        path.write_bytes(raw)
        with mock.patch.object(referee, "MAX_ENTRIES", 1):
            with mock.patch.object(referee.zipfile, "ZipFile", side_effect=AssertionError(
                "ZipFile must not allocate entries before the independent count cap"
            )):
                self.assert_invalid(path)

    def test_compression_ratio_budget(self):
        entries = dict(self.entries)
        entries["large-report.md"] = b"x" * 200_000
        path = self.archive(entries, compression=zipfile.ZIP_DEFLATED)
        self.assert_invalid(path)

    def test_no_sensitive_metadata_or_content_in_error_report(self):
        canary = "PRIVATE_CANARY_DO_NOT_ECHO"
        binding = copy.deepcopy(self.binding)
        binding["snapshot"]["resp_head"] = canary
        binding["snapshot"]["url"] = "https://lab.invalid/" + canary
        entries = self.with_manifest(binding)
        entries[canary + ".exe"] = canary.encode()
        result = self.assert_invalid(self.archive(entries))
        self.assertNotIn(canary, json.dumps(result))

    def test_cli_status_json_and_exit_codes(self):
        path = self.archive()
        pin = digest(path.read_bytes())
        for extra, expected_code, expected_status in (
            (["--expected-sha256", pin], 0, "VERIFIED"),
            ([], 2, "INCONCLUSIVE"),
            (["--expected-sha256", "0" * 64], 1, "INVALID"),
        ):
            with self.subTest(extra=extra):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = referee.main(["verify", str(path)] + extra)
                result = json.loads(output.getvalue())
                self.assertEqual(code, expected_code)
                self.assertEqual(result["status"], expected_status)
                self.assert_safe_claim(result)


if __name__ == "__main__":
    unittest.main()
