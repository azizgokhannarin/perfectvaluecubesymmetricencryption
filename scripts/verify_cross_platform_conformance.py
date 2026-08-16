#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generator", required=True)
    parser.add_argument(
        "--expected", default="test-vectors/cross-platform-conformance-v1.json"
    )
    args = parser.parse_args()

    expected = json.loads(Path(args.expected).read_text(encoding="utf-8"))
    if expected.get("format") != "pvc-rotsymenc1-cross-platform-conformance-v1":
        raise ValueError("unexpected conformance format")

    generator = str(Path(args.generator).resolve())
    cases = int(expected["cases"])
    with tempfile.TemporaryDirectory(prefix="pvc-rotsymenc1-conformance-") as directory:
        transcript = Path(directory) / "transcript.bin"
        completed = subprocess.run(
            [generator, "--output", str(transcript), "--count", str(cases)],
            check=True,
            text=True,
            capture_output=True,
        )
        actual_size = transcript.stat().st_size
        actual_sha256 = sha256_file(transcript)

    expected_size = int(expected["transcript_bytes"])
    expected_sha256 = str(expected["sha256"])
    if actual_size != expected_size or actual_sha256 != expected_sha256:
        print(completed.stdout, end="", file=sys.stderr)
        print(
            f"conformance mismatch: bytes={actual_size} sha256={actual_sha256}",
            file=sys.stderr,
        )
        print(
            f"expected: bytes={expected_size} sha256={expected_sha256}",
            file=sys.stderr,
        )
        return 1

    print(completed.stdout, end="")
    print(
        f"conformance_match=1 transcript_bytes={actual_size} sha256={actual_sha256}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
