#!/usr/bin/env python3
"""Validate and summarize PVC-RotSymEnc-1 performance campaign records."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


def load_record(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as source:
        record = json.load(source)
    if record.get("runner_version") != 1:
        raise ValueError(f"{path}: unsupported runner version")

    campaign = record.get("campaign")
    results = record.get("results")
    if not isinstance(campaign, dict) or not isinstance(results, list):
        raise ValueError(f"{path}: missing campaign or results")

    sizes = campaign.get("sizes")
    tags = campaign.get("tag_bits")
    operations = campaign.get("operations")
    if not isinstance(sizes, list) or not isinstance(tags, list) or not isinstance(operations, list):
        raise ValueError(f"{path}: invalid campaign dimensions")
    expected = {
        (operation, tag_bits, message_size)
        for message_size in sizes
        for tag_bits in tags
        for operation in operations
    }
    observed = {
        (row.get("operation"), row.get("tag_bits"), row.get("message_bytes"))
        for row in results
        if isinstance(row, dict)
    }
    if len(results) != len(expected) or observed != expected:
        raise ValueError(
            f"{path}: expected {len(expected)} unique cases, observed {len(results)} rows "
            f"and {len(observed)} unique cases"
        )
    for row in results:
        if row.get("construction_version") != "0.1.0-draft":
            raise ValueError(f"{path}: construction version mismatch")
        if row.get("ndebug") is not True:
            raise ValueError(f"{path}: non-release benchmark row")
        if row.get("message_bytes") == 0:
            if row.get("mebibytes_per_second_median") is not None:
                raise ValueError(f"{path}: zero-byte throughput must be null")
        elif row.get("mebibytes_per_second_median", 0) <= 0:
            raise ValueError(f"{path}: non-positive throughput")
        if row.get("latency_nanoseconds_median", 0) <= 0:
            raise ValueError(f"{path}: non-positive latency")
    return record


def format_number(value: Any, digits: int = 6) -> str:
    if value is None:
        return ""
    return f"{float(value):.{digits}f}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("records", nargs="+", type=Path)
    parser.add_argument("--verify-only", action="store_true")
    arguments = parser.parse_args()

    records = [(path, load_record(path)) for path in arguments.records]
    if arguments.verify_only:
        for path, record in records:
            print(f"verified {len(record['results'])} performance cases: {path}")
        return 0

    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(
        (
            "record",
            "compiler",
            "operation",
            "tag_bits",
            "message_bytes",
            "latency_ms_median",
            "mib_per_second_median",
            "tsc_ticks_per_byte_median",
            "peak_rss_kib",
        )
    )
    for path, record in records:
        for row in record["results"]:
            writer.writerow(
                (
                    path.name,
                    f"{row['compiler_id']}-{row['compiler_version']}",
                    row["operation"],
                    row["tag_bits"],
                    row["message_bytes"],
                    format_number(row["latency_nanoseconds_median"] / 1.0e6),
                    format_number(row["mebibytes_per_second_median"]),
                    format_number(row["tsc_ticks_per_byte_median"]),
                    row["peak_rss_after_measurement_kib"],
                )
            )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
