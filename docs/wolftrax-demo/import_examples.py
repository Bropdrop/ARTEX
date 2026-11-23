"""Derive synthetic import examples from before.json, without contacting ARTEX."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new output directory")
    args = parser.parse_args()
    source = json.loads(Path(__file__).with_name("before.json").read_bytes())
    if source.get("synthetic") is not True or source["count"] < 2:
        parser.error("expected the checked-in synthetic demo capture")
    out = args.destination
    out.mkdir(parents=True, exist_ok=False)

    def write(name, data):
        (out / (name + ".json")).write_bytes(data)

    def encode(value):
        return json.dumps(value, ensure_ascii=False).encode("utf-8")

    # Each valid variant changes one field of the asserted capture. They are
    # derived import examples; SHA256SUMS covers the original producer files.
    write("different-source", encode({**source, "source_namespace": "synthetic-other-library"}))
    write("unknown-incarnation", encode({**source, "dataset_incarnation": None}))
    records = [dict(record) for record in source["records"]]
    records[0]["status"] = "demo_future_decision"
    write("unknown-decision", encode({**source, "records": records}))

    raw = encode(source)
    write("truncated", raw[:-1])
    write("duplicate-key", b'{"count":0,' + raw[1:])
    write("duplicate-id", encode({**source, "records": [source["records"][0]] * 2, "count": 2}))
    write("too-deep", b'{"nested":' + b"[" * 64 + b"0" + b"]" * 64 + b"}")
    # Valid JSON whitespace takes the input just beyond the on-disk byte limit.
    write("too-large", raw.ljust(4 * 1024 * 1024 + 1))
    write("unsupported-schema", encode({**source, "schema": "wolftrax.authority.v999"}))


if __name__ == "__main__":
    main()
