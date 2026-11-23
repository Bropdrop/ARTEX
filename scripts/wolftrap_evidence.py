#!/usr/bin/env python3
"""Offline integrity referee for ARTEX finding ``md-zip`` exports.

The supported profile is the exporter and database structs at ARTEX commit
d235be850e9b34247ddb566686c47e6d4e4f0daf: server/finding_traffic_export.go and
db/finding_traffic.go. This is NOT the unrelated versioned task-archive format.

No network requests, subprocesses, extraction, or evidence execution occur.
An externally supplied archive SHA-256 establishes only consistency with those
bytes. It does not authenticate their producer, establish permission to test a
target, or reproduce a vulnerability. Every result preserves those distinctions.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import stat
import struct
import sys
import unicodedata
import zipfile
import zlib


MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_ENTRY_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_ENTRIES = 2048
MAX_COMPRESSION_RATIO = 100
MAX_MANIFEST_BYTES = 256 * 1024
MAX_PATH_BYTES = 1024
INT64_MAX = 2**63 - 1
PROFILE = "artex-md-zip-d235be850e9b34247ddb566686c47e6d4e4f0daf"

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_POSITIVE_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
_EVIDENCE_PATH = re.compile(
    r"evidence/([1-9][0-9]{0,18})/([1-9][0-9]{0,18})/"
    r"(manifest\.json|request\.http|response\.http|request\.bin|response\.bin)\Z"
)
_TIMESTAMP = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T"
    r"([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_METHOD = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_BINDING_FIELDS = {
    "id", "finding_id", "snapshot_id", "role", "note", "position", "created_at", "snapshot"
}
_SNAPSHOT_FIELDS = {
    "id", "source_traffic_id", "captured_at", "url", "method", "status", "content_type",
    "req_hash", "resp_hash", "req_len", "resp_len", "created_at",
}
_SNAPSHOT_OPTIONAL = {"req_head", "resp_head", "rewritten", "rewrite_rule_ids"}
_BINDING_MEMBERS = {"manifest.json", "request.http", "response.http", "request.bin", "response.bin"}


class _Rejected(Exception):
    """Fixed diagnostics only: never incorporate target data or exception text."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _reject(code: str, message: str) -> None:
    raise _Rejected(code, message)


def _result() -> dict:
    return {
        "profile": PROFILE,
        "status": "INCONCLUSIVE",
        "evidence_integrity": "NOT_ASSESSED",
        "claim_status": "CLAIM_NOT_ASSESSED",
        "origin_status": "UNAUTHENTICATED",
        "anchor_status": "UNPINNED",
        "archive_sha256": None,
        "bindings_verified": 0,
        "findings_with_evidence": 0,
        "report_files": 0,
        "entries_checked": 0,
        "rewritten_bindings": 0,
        "errors": [],
        "limitations": [
            "Integrity checks do not reproduce or validate a vulnerability claim.",
            "A caller-supplied SHA-256 pin is a consistency anchor, not a signature or identity proof.",
            "An unpinned archive and its embedded hashes are untrusted assertions by the same producer.",
            "Snapshot IDs exclude creation time and rewrite provenance; an external archive pin covers their bytes only.",
            "Report prose, scope authorization, capture origin, freshness, and evidence completeness are not assessed.",
        ],
    }


def _immutable_archive(path: os.PathLike | str) -> bytes:
    # Nonblocking open plus a regular-file check avoids hanging on pipes/devices.
    # Hashing and ZIP inspection subsequently use the very same immutable bytes.
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            _reject("INPUT_NOT_REGULAR", "The input must be a regular archive file.")
        if info.st_size > MAX_ARCHIVE_BYTES:
            _reject("ARCHIVE_TOO_LARGE", "The compressed archive exceeds the supported size limit.")
        data = stream.read(MAX_ARCHIVE_BYTES + 1)
        if len(data) > MAX_ARCHIVE_BYTES:
            _reject("ARCHIVE_TOO_LARGE", "The compressed archive exceeds the supported size limit.")
    return data


def _zip_preflight(data: bytes) -> tuple[int, int]:
    # Bound central-directory allocation before ZipFile creates ZipInfo objects.
    # The bounded Go md-zip exporter produces ordinary single-disk archives with
    # no archive comment. ZIP64, self-extracting files and trailing data are not
    # supported by this profile, even if some general-purpose readers accept them.
    if len(data) < 22 or data[-22:-18] != b"PK\x05\x06":
        _reject("UNSUPPORTED_ZIP", "A complete comment-free ZIP end record is required.")
    _, disk, directory_disk, disk_count, count, size, offset, comment = struct.unpack(
        "<4s4H2LH", data[-22:]
    )
    if disk or directory_disk or disk_count != count or comment:
        _reject("UNSUPPORTED_ZIP", "Multi-disk archives and archive comments are not supported.")
    if count == 0xFFFF or size == 0xFFFFFFFF or offset == 0xFFFFFFFF:
        _reject("UNSUPPORTED_ZIP", "ZIP64 archives are outside this bounded export profile.")
    if count > MAX_ENTRIES:
        _reject("TOO_MANY_ENTRIES", "The archive contains more entries than the supported limit.")
    if offset + size != len(data) - 22 or size < count * 46:
        _reject("INVALID_ZIP", "The ZIP directory layout is inconsistent.")
    if count and (data[:4] != b"PK\x03\x04" or data[offset:offset + 4] != b"PK\x01\x02"):
        _reject("INVALID_ZIP", "The ZIP directory or first local entry is missing.")
    # Do not trust the EOCD's count: ZipFile actually walks the directory until
    # its byte-size is consumed. A dishonest low count could otherwise cause
    # allocation of hundreds of thousands of ZipInfo objects before our check.
    cursor, actual_count, end = offset, 0, offset + size
    while cursor < end:
        if cursor + 46 > end or data[cursor:cursor + 4] != b"PK\x01\x02":
            _reject("INVALID_ZIP", "The ZIP directory contains an incomplete entry.")
        name_size, extra_size, comment_size, entry_disk = struct.unpack_from("<4H", data, cursor + 28)
        if not 0 < name_size <= MAX_PATH_BYTES or entry_disk:
            _reject("INVALID_ZIP", "A ZIP directory entry has an invalid name size or disk number.")
        cursor += 46 + name_size + extra_size + comment_size
        actual_count += 1
        if cursor > end:
            _reject("INVALID_ZIP", "The ZIP directory contains a truncated entry.")
        if actual_count > MAX_ENTRIES:
            _reject("TOO_MANY_ENTRIES", "The archive contains more entries than the supported limit.")
    if actual_count != count:
        _reject("INVALID_ZIP", "The ZIP directory entry count disagrees with its end record.")
    return count, offset


def _check_name(info: zipfile.ZipInfo) -> None:
    name = info.filename
    if info.orig_filename != name or not name or len(name.encode("utf-8")) > MAX_PATH_BYTES:
        _reject("UNSAFE_PATH", "An archive member name is invalid or exceeds the path limit.")
    if "\\" in name or ":" in name or name.startswith("/"):
        _reject("UNSAFE_PATH", "Absolute, drive-qualified and backslash archive paths are forbidden.")
    if any(part in ("", ".", "..") for part in name.split("/")):
        _reject("UNSAFE_PATH", "Archive paths must have ordinary relative components.")
    if any(unicodedata.category(c).startswith("C") for c in name):
        _reject("UNSAFE_PATH", "Control and non-scalar characters are forbidden in archive paths.")
    mode = info.external_attr >> 16
    if stat.S_IFMT(mode) not in (0, stat.S_IFREG) or info.is_dir() or info.external_attr & 0x10:
        _reject("SPECIAL_ENTRY", "Only regular file entries are supported; links and directories are forbidden.")
    if info.flag_bits & (0x1 | 0x40):
        _reject("ENCRYPTED_ENTRY", "Encrypted archive entries are forbidden.")
    if info.flag_bits & ~(0x800 | 0x8 | 0x6):
        _reject("UNSUPPORTED_ZIP", "An archive entry uses unsupported ZIP flags.")
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        _reject("UNSUPPORTED_COMPRESSION", "Only stored and deflated archive entries are supported.")
    if info.file_size > MAX_ENTRY_BYTES:
        _reject("ENTRY_TOO_LARGE", "An archive member exceeds the supported size limit.")
    if info.file_size > max(1, info.compress_size) * MAX_COMPRESSION_RATIO:
        _reject("COMPRESSION_RATIO", "An archive member exceeds the supported decompression ratio.")
    if info.compress_size < 0 or info.file_size < 0:
        _reject("INVALID_ZIP", "An archive member has an invalid size.")
    _check_extra(info.extra)


def _check_extra(extra: bytes) -> None:
    while extra:
        if len(extra) < 4:
            _reject("INVALID_ZIP", "An archive entry has malformed extra metadata.")
        kind, length = struct.unpack("<HH", extra[:4])
        if length > len(extra) - 4:
            _reject("INVALID_ZIP", "An archive entry has truncated extra metadata.")
        if kind == 1:
            _reject("UNSUPPORTED_ZIP", "ZIP64 archives are outside this bounded export profile.")
        extra = extra[4 + length:]


def _members(archive: zipfile.ZipFile, expected_count: int, directory_offset: int) -> tuple[dict, dict, int]:
    infos = archive.infolist()
    if len(infos) != expected_count or archive.start_dir != directory_offset:
        _reject("INVALID_ZIP", "The ZIP directory count or position is inconsistent.")
    if infos and min(i.header_offset for i in infos) != 0:
        _reject("INVALID_ZIP", "Data before the first archive entry is unsupported.")
    by_name, groups, seen_offsets = {}, {}, set()
    total, reports = 0, 0
    for info in infos:
        _check_name(info)
        name = info.filename
        if name in by_name:
            _reject("DUPLICATE_ENTRY", "Duplicate archive member names are forbidden.")
        if info.header_offset in seen_offsets or not 0 <= info.header_offset < directory_offset:
            _reject("INVALID_ZIP", "Archive entries have inconsistent local header positions.")
        seen_offsets.add(info.header_offset)
        by_name[name] = info
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            _reject("TOTAL_TOO_LARGE", "The archive exceeds the total uncompressed size limit.")
        match = _EVIDENCE_PATH.fullmatch(name)
        if match:
            finding_id, binding_id, leaf = match.groups()
            if int(finding_id) > INT64_MAX or int(binding_id) > INT64_MAX:
                _reject("INVALID_METADATA", "An evidence path identifier is outside the database range.")
            groups.setdefault((finding_id, binding_id), {})[leaf] = info
            if leaf == "manifest.json" and info.file_size > MAX_MANIFEST_BYTES:
                _reject("MANIFEST_TOO_LARGE", "An evidence manifest exceeds the supported size limit.")
        elif "/" not in name and name.endswith(".md"):
            reports += 1
        else:
            _reject("UNKNOWN_ENTRY", "The archive contains a member outside the supported md-zip profile.")
    if not reports:
        _reject("MISSING_REPORT", "An ARTEX md-zip export must include a top-level Markdown report.")
    ids = set()
    for (_, binding_id), group in groups.items():
        if set(group) != _BINDING_MEMBERS:
            _reject("MISSING_EVIDENCE", "A binding is missing one or more of its five required evidence files.")
        if binding_id in ids:
            _reject("DUPLICATE_BINDING", "An evidence binding identifier is reused across findings.")
        ids.add(binding_id)
    return by_name, groups, reports


def _strict_streams(data: bytes, by_name: dict, directory_offset: int) -> None:
    """Validate the complete local layout and actual compressed streams.

    ZipExtFile truncates decompressed output at the *declared* file size. A
    forged smaller size plus the prefix's CRC can therefore hide an expanded
    suffix from a normal read. Decode each compressed span independently with
    an explicit bound, and require the entire stream to end at that boundary.
    """
    ordered = sorted(by_name.values(), key=lambda info: info.header_offset)
    for index, info in enumerate(ordered):
        offset = info.header_offset
        next_offset = ordered[index + 1].header_offset if index + 1 < len(ordered) else directory_offset
        if offset + 30 > next_offset:
            _reject("INVALID_ZIP", "An archive entry has an incomplete local header.")
        signature, version, flags, method, dos_time, dos_date, crc, compressed_size, size, name_size, extra_size = struct.unpack_from(
            "<4s5H3L2H", data, offset
        )
        if signature != b"PK\x03\x04":
            _reject("INVALID_ZIP", "An archive local header signature is invalid.")
        if flags != info.flag_bits or method != info.compress_type or version != info.extract_version + (info.reserved << 8):
            _reject("LOCAL_HEADER_MISMATCH", "Local and central ZIP entry metadata disagree.")
        year, month, day, hour, minute, second = info.date_time
        if dos_time != (hour << 11 | minute << 5 | second // 2) or dos_date != ((year - 1980) << 9 | month << 5 | day):
            _reject("LOCAL_HEADER_MISMATCH", "Local and central ZIP timestamps disagree.")
        name_start = offset + 30
        extra_start = name_start + name_size
        body_start = extra_start + extra_size
        body_end = body_start + info.compress_size
        if not 0 < name_size <= MAX_PATH_BYTES or body_end > next_offset:
            _reject("INVALID_ZIP", "Local entry lengths overlap or exceed the archive layout.")
        encoded_name = info.orig_filename.encode("utf-8" if flags & 0x800 else "cp437")
        if data[name_start:extra_start] != encoded_name:
            _reject("LOCAL_HEADER_MISMATCH", "Local and central ZIP member names disagree.")
        _check_extra(data[extra_start:body_start])
        expected = (info.CRC, info.compress_size, info.file_size)
        if flags & 0x8:
            # Go's streaming writer uses a descriptor and zeroes these fields.
            # A writer may also put the eventual values in the local header.
            if any(local not in (0, actual) for local, actual in zip((crc, compressed_size, size), expected)):
                _reject("LOCAL_HEADER_MISMATCH", "A streamed entry has inconsistent local sizes or CRC.")
            descriptor = data[body_end:next_offset]
            if len(descriptor) == 16 and descriptor[:4] == b"PK\x07\x08":
                descriptor = descriptor[4:]
            if len(descriptor) != 12 or struct.unpack("<3L", descriptor) != expected:
                _reject("INVALID_DESCRIPTOR", "A streaming data descriptor is missing or inconsistent.")
        elif (crc, compressed_size, size) != expected or body_end != next_offset:
            _reject("LOCAL_HEADER_MISMATCH", "An entry has inconsistent local metadata or trailing bytes.")
        compressed = memoryview(data)[body_start:body_end]
        if method == zipfile.ZIP_STORED:
            if info.compress_size != info.file_size:
                _reject("INVALID_COMPRESSED_STREAM", "A stored ZIP entry has inconsistent lengths.")
            decoded = compressed
        else:
            decompressor = zlib.decompressobj(-15)
            decoded = decompressor.decompress(compressed, info.file_size + 1)
            if (len(decoded) != info.file_size or not decompressor.eof
                    or decompressor.unconsumed_tail or decompressor.unused_data):
                _reject("INVALID_COMPRESSED_STREAM", "A deflated entry has excess, incomplete or trailing compressed data.")
        if len(decoded) != info.file_size or zlib.crc32(decoded) & 0xFFFFFFFF != info.CRC:
            _reject("INVALID_ZIP", "The complete decoded entry fails its length or CRC check.")


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = MAX_ENTRY_BYTES) -> bytes:
    with archive.open(info, "r") as stream:
        data = stream.read(limit + 1)
        if len(data) > limit or len(data) != info.file_size:
            _reject("ENTRY_SIZE_MISMATCH", "A decoded archive member has an inconsistent or excessive length.")
        # Reaching EOF is necessary for CRC checking, including empty members.
        if stream.read(1):
            _reject("ENTRY_SIZE_MISMATCH", "A decoded archive member exceeds its declared length.")
    return data


def _unique_object(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("DUPLICATE_JSON_KEY", "Duplicate JSON object keys are forbidden.")
        result[key] = value
    return result


def _nonfinite(_: str) -> None:
    _reject("INVALID_JSON", "Nonfinite JSON numbers are forbidden.")


def _fields(value: object, required: set, optional: set | None = None) -> None:
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - (optional or set()):
        _reject("UNKNOWN_SCHEMA", "A manifest does not match the supported ARTEX binding schema.")


def _string(value: object, *, nonempty: bool = False) -> str:
    if type(value) is not str or (nonempty and not value) or "\x00" in value:
        _reject("INVALID_METADATA", "An evidence text field has an invalid type or value.")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        _reject("INVALID_METADATA", "Evidence metadata must contain Unicode scalar text.")
    return value


def _integer(value: object, minimum: int = 0, maximum: int = INT64_MAX) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        _reject("INVALID_METADATA", "An evidence integer field has an invalid type or range.")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _HASH.fullmatch(value):
        _reject("INVALID_METADATA", "An evidence digest must be a lowercase SHA-256 hexadecimal string.")
    return value


def _timestamp(value: object) -> None:
    _string(value)
    match = _TIMESTAMP.fullmatch(value)
    if not match:
        _reject("INVALID_METADATA", "An evidence timestamp is not an RFC3339 timestamp.")
    try:
        datetime.datetime(*(int(v) for v in match.groups()[:6]))
        zone = match.group(7)
        if zone != "Z" and (int(zone[1:3]) > 23 or int(zone[4:6]) > 59):
            raise ValueError
    except ValueError:
        _reject("INVALID_METADATA", "An evidence timestamp has an invalid calendar or offset value.")


def _snapshot_digest(snapshot: dict) -> str:
    # This order is the Go TrafficEvidenceSnapshot declaration, not sorted JSON.
    # Go encoding/json escapes HTML and U+2028/U+2029, but retains other UTF-8.
    normalized = {"id": ""}
    for key in ("source_traffic_id", "captured_at", "url", "method", "status", "content_type"):
        normalized[key] = snapshot[key]
    for key in ("req_head", "resp_head"):
        if snapshot.get(key, ""):
            normalized[key] = snapshot[key]
    for key in ("req_hash", "resp_hash", "req_len", "resp_len"):
        normalized[key] = snapshot[key]
    normalized["created_at"] = "0001-01-01T00:00:00Z"
    encoded = json.dumps(normalized, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    for source, replacement in (("<", "\\u003c"), (">", "\\u003e"), ("&", "\\u0026"),
                                ("\u2028", "\\u2028"), ("\u2029", "\\u2029")):
        encoded = encoded.replace(source, replacement)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _manifest(data: bytes, finding_id: str, binding_id: str) -> dict:
    if len(data) > MAX_MANIFEST_BYTES:
        _reject("MANIFEST_TOO_LARGE", "An evidence manifest exceeds the supported size limit.")
    binding = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_nonfinite)
    _fields(binding, _BINDING_FIELDS)
    for key, expected in (("id", binding_id), ("finding_id", finding_id)):
        value = binding[key]
        if type(value) is not str or not _POSITIVE_ID.fullmatch(value) or value != expected:
            _reject("ID_MISMATCH", "A manifest identifier does not match its archive path.")
    _digest(binding["snapshot_id"])
    if type(binding["role"]) is not str or binding["role"] not in ("baseline", "proof", "verification", "supporting"):
        _reject("INVALID_METADATA", "An evidence binding has an unsupported role.")
    _string(binding["note"])
    _integer(binding["position"])
    _timestamp(binding["created_at"])
    snapshot = binding["snapshot"]
    _fields(snapshot, _SNAPSHOT_FIELDS, _SNAPSHOT_OPTIONAL)
    for key in ("id", "req_hash", "resp_hash"):
        _digest(snapshot[key])
    for key in ("source_traffic_id", "url", "method"):
        _string(snapshot[key], nonempty=True)
    if not _METHOD.fullmatch(snapshot["method"]):
        _reject("INVALID_METADATA", "An evidence HTTP method is not a valid token.")
    for key in ("content_type", "req_head", "resp_head"):
        _string(snapshot.get(key, ""))
    _integer(snapshot["captured_at"], -(2**63))
    _integer(snapshot["status"], 0, 999)
    for key in ("req_len", "resp_len"):
        _integer(snapshot[key], 0, MAX_ENTRY_BYTES)
    _timestamp(snapshot["created_at"])
    if "rewritten" in snapshot and type(snapshot["rewritten"]) is not bool:
        _reject("INVALID_METADATA", "The rewrite indicator must be a JSON boolean.")
    if "rewrite_rule_ids" in snapshot:
        ids = snapshot["rewrite_rule_ids"]
        if type(ids) is not list or len(ids) > MAX_ENTRIES:
            _reject("INVALID_METADATA", "Rewrite provenance must be a bounded integer list.")
        for rule_id in ids:
            _integer(rule_id, 1)
    if snapshot["id"] != binding["snapshot_id"] or snapshot["id"] != _snapshot_digest(snapshot):
        _reject("SNAPSHOT_HASH_MISMATCH", "The snapshot metadata does not match its declared SHA-256 identifier.")
    return binding


def _verify_binding(archive: zipfile.ZipFile, key: tuple, members: dict) -> bool:
    binding = _manifest(_read_member(archive, members["manifest.json"], MAX_MANIFEST_BYTES), *key)
    snapshot = binding["snapshot"]
    for side, prefix in (("request", "req"), ("response", "resp")):
        body = _read_member(archive, members[side + ".bin"])
        if len(body) != snapshot[prefix + "_len"]:
            _reject("BODY_LENGTH_MISMATCH", "An evidence body length disagrees with its manifest.")
        if hashlib.sha256(body).hexdigest() != snapshot[prefix + "_hash"]:
            _reject("BODY_HASH_MISMATCH", "An evidence body SHA-256 disagrees with its manifest.")
        http = _read_member(archive, members[side + ".http"])
        header = snapshot.get(prefix + "_head", "").rstrip("\r\n").encode("utf-8") + b"\n\n"
        if len(http) != len(header) + len(body) or not http.startswith(header) or http[len(header):] != body:
            _reject("HTTP_BODY_MISMATCH", "An HTTP evidence view disagrees with its recorded headers and body.")
    return snapshot.get("rewritten", False)


def verify_archive(path: os.PathLike | str, expected_sha256: str | None = None) -> dict:
    """Return a bounded, content-free JSON-serializable verification report.

    VERIFIED means an externally pinned archive passed the supported integrity
    profile. It never means authenticated origin, authorized activity or a
    reproduced claim. Internally consistent but unpinned data is INCONCLUSIVE.
    Invalid inputs return INVALID without raising ordinary parsing/I/O errors.
    """
    result = _result()
    try:
        if expected_sha256 is not None and (
            type(expected_sha256) is not str or not _HASH.fullmatch(expected_sha256)
        ):
            result["anchor_status"] = "INVALID_ANCHOR"
            _reject("INVALID_ANCHOR", "The supplied archive pin must be lowercase SHA-256 hexadecimal.")
        data = _immutable_archive(path)
        result["archive_sha256"] = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None:
            if expected_sha256 != result["archive_sha256"]:
                result["anchor_status"] = "MISMATCH"
                _reject("ARCHIVE_HASH_MISMATCH", "The archive does not match the externally supplied SHA-256 pin.")
            result["anchor_status"] = "EXTERNALLY_PINNED_SHA256"
        count, offset = _zip_preflight(data)
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            by_name, groups, reports = _members(archive, count, offset)
            _strict_streams(data, by_name, offset)
            result["report_files"] = reports
            # Read report bytes as inert data solely for size and CRC checks.
            for name, info in by_name.items():
                if "/" not in name:
                    _read_member(archive, info)
            rewritten = 0
            for key, members in groups.items():
                rewritten += int(_verify_binding(archive, key, members))
            result["entries_checked"] = len(by_name)
            result["bindings_verified"] = len(groups)
            result["findings_with_evidence"] = len({key[0] for key in groups})
            result["rewritten_bindings"] = rewritten
        if not groups:
            result["errors"].append({"code": "NO_EVIDENCE", "message": "No complete evidence binding was available to assess."})
            return result
        result["evidence_integrity"] = "EVIDENCE_INTEGRITY_VERIFIED"
        if expected_sha256 is None:
            result["errors"].append({"code": "UNPINNED_ARCHIVE", "message": "An independently obtained archive SHA-256 pin is required for a verified integrity result."})
        else:
            result["status"] = "VERIFIED"
        return result
    except _Rejected as exc:
        code, message = exc.code, exc.message
    except (OSError, TypeError):
        code, message = "INPUT_ERROR", "The archive could not be read as a bounded regular file."
    except (zipfile.BadZipFile, zipfile.LargeZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError):
        code, message = "INVALID_ZIP", "Archive structure, decompression or CRC validation failed."
    except (ValueError, UnicodeError, OverflowError, RecursionError, struct.error):
        code, message = "INVALID_FORMAT", "Archive or manifest data is malformed or outside the supported profile."
    result["status"] = "INVALID"
    result["evidence_integrity"] = "INVALID"
    result["bindings_verified"] = 0
    result["findings_with_evidence"] = 0
    result["rewritten_bindings"] = 0
    result["errors"].append({"code": code, "message": message})
    return result


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        _reject("INVALID_ARGUMENTS", "Use: wolftrap_evidence.py verify PATH [--expected-sha256 HASH].")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("command", choices=["verify"])
    parser.add_argument("path")
    parser.add_argument("--expected-sha256", help="Archive SHA-256 obtained through an independent trusted channel")
    try:
        args = parser.parse_args(argv)
        result = verify_archive(args.path, args.expected_sha256)
    except _Rejected as exc:
        result = _result()
        result.update(status="INVALID", evidence_integrity="INVALID")
        result["errors"].append({"code": exc.code, "message": exc.message})
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return {"VERIFIED": 0, "INVALID": 1, "INCONCLUSIVE": 2}[result["status"]]


if __name__ == "__main__":
    sys.exit(main())
