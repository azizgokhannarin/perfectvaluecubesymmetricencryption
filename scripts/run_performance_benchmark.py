#!/usr/bin/env python3
"""Run isolated PVC-RotSymEnc-1 benchmark cases and retain structured results."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any


DEFAULT_SIZES = (0, 16, 64, 256, 1024, 4096, 65536, 1048576)
DEFAULT_TAGS = (128, 192, 256)
DEFAULT_OPERATIONS = ("seal", "open-success")


def parse_integer_list(text: str, *, name: str) -> tuple[int, ...]:
    try:
        values = tuple(int(item, 10) for item in text.split(","))
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"invalid {name}: {text}") from error
    if not values or any(value < 0 for value in values):
        raise argparse.ArgumentTypeError(f"{name} must contain non-negative integers")
    return values


def parse_operations(text: str) -> tuple[str, ...]:
    values = tuple(text.split(","))
    if not values or any(value not in DEFAULT_OPERATIONS for value in values):
        raise argparse.ArgumentTypeError("operations must contain seal and/or open-success")
    return values


def command_output(command: list[str]) -> str | None:
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip()


def read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return None


def cpu_model() -> str | None:
    cpuinfo = read_text(Path("/proc/cpuinfo"))
    if cpuinfo is None:
        return platform.processor() or None
    for line in cpuinfo.splitlines():
        if line.startswith("model name") and ":" in line:
            return line.split(":", 1)[1].strip()
    return platform.processor() or None


def affinity() -> list[int] | None:
    if not hasattr(os, "sched_getaffinity"):
        return None
    return sorted(os.sched_getaffinity(0))


def cpufreq_value(cpu: int | None, field: str) -> str | None:
    if cpu is None:
        return None
    return read_text(Path(f"/sys/devices/system/cpu/cpu{cpu}/cpufreq/{field}"))


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def benchmark_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pinned_preexec(cpu: int | None):
    if cpu is None or not hasattr(os, "sched_setaffinity"):
        return None

    def set_affinity() -> None:
        os.sched_setaffinity(0, {cpu})

    return set_affinity


def execute_case(
    benchmark: Path,
    *,
    operation: str,
    tag_bits: int,
    message_size: int,
    samples: int,
    target_ms: int,
    maximum_iterations: int,
    pinned_cpu: int | None,
    timeout_seconds: int,
) -> dict[str, Any]:
    executable_operation = "open" if operation == "open-success" else operation
    command = [
        str(benchmark),
        "--operation",
        executable_operation,
        "--tag-bits",
        str(tag_bits),
        "--size",
        str(message_size),
        "--samples",
        str(samples),
        "--target-ms",
        str(target_ms),
        "--max-iterations",
        str(maximum_iterations),
    ]
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        preexec_fn=pinned_preexec(pinned_cpu),
    )
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if len(lines) != 1:
        raise RuntimeError(f"benchmark emitted {len(lines)} non-empty stdout lines")
    parsed = json.loads(lines[0])
    expected = (operation, tag_bits, message_size, samples)
    observed = (
        parsed.get("operation"),
        parsed.get("tag_bits"),
        parsed.get("message_bytes"),
        parsed.get("samples"),
    )
    if observed != expected:
        raise RuntimeError(f"benchmark result mismatch: expected {expected}, observed {observed}")
    if parsed.get("ndebug") is not True:
        raise RuntimeError("benchmark binary is not a release/NDEBUG build")
    return parsed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--sizes",
        type=lambda text: parse_integer_list(text, name="sizes"),
        default=DEFAULT_SIZES,
    )
    parser.add_argument(
        "--tags",
        type=lambda text: parse_integer_list(text, name="tags"),
        default=DEFAULT_TAGS,
    )
    parser.add_argument("--operations", type=parse_operations, default=DEFAULT_OPERATIONS)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--large-samples", type=int, default=3)
    parser.add_argument("--large-threshold", type=int, default=65536)
    parser.add_argument("--target-ms", type=int, default=100)
    parser.add_argument("--max-iterations", type=int, default=1 << 20)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--cpu", type=int)
    parser.add_argument("--no-pin", action="store_true")
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--require-tsc", action="store_true")
    arguments = parser.parse_args()

    benchmark = arguments.benchmark.resolve()
    if not benchmark.is_file() or not os.access(benchmark, os.X_OK):
        parser.error(f"benchmark is not executable: {benchmark}")
    if arguments.samples <= 0 or arguments.large_samples <= 0 or arguments.target_ms <= 0:
        parser.error("samples, large-samples, and target-ms must be positive")
    if arguments.large_threshold < 0:
        parser.error("large-threshold must be non-negative")
    if arguments.max_iterations <= 0 or arguments.timeout_seconds <= 0:
        parser.error("max-iterations and timeout-seconds must be positive")
    if any(tag not in DEFAULT_TAGS for tag in arguments.tags):
        parser.error("tags must be selected from 128, 192, and 256")

    allowed_cpus = affinity()
    if arguments.no_pin:
        pinned_cpu = None
    elif arguments.cpu is not None:
        if allowed_cpus is not None and arguments.cpu not in allowed_cpus:
            parser.error(f"CPU {arguments.cpu} is outside the allowed affinity {allowed_cpus}")
        pinned_cpu = arguments.cpu
    else:
        pinned_cpu = allowed_cpus[0] if allowed_cpus else None

    git_status = command_output(["git", "status", "--porcelain", "--untracked-files=no"])
    if arguments.require_clean and git_status:
        parser.error("tracked working tree is dirty; commit the benchmark definition first")

    record: dict[str, Any] = {
        "runner_version": 1,
        "campaign": {
            "construction_version": "0.1.0-draft",
            "seed": "0x50455246424D4B31",
            "sizes": list(arguments.sizes),
            "tag_bits": list(arguments.tags),
            "operations": list(arguments.operations),
            "associated_data_bytes": 32,
            "samples_below_large_threshold": arguments.samples,
            "samples_at_or_above_large_threshold": arguments.large_samples,
            "large_threshold_bytes": arguments.large_threshold,
            "target_sample_milliseconds": arguments.target_ms,
            "maximum_iterations": arguments.max_iterations,
            "case_order": "size-then-tag-then-operation",
        },
        "environment": {
            "started_utc": utc_now(),
            "platform": platform.platform(),
            "uname": list(platform.uname()),
            "python": platform.python_version(),
            "cpu_model": cpu_model(),
            "allowed_cpus": allowed_cpus,
            "pinned_cpu": pinned_cpu,
            "scaling_governor": cpufreq_value(pinned_cpu, "scaling_governor"),
            "scaling_driver": cpufreq_value(pinned_cpu, "scaling_driver"),
            "scaling_min_freq_khz": cpufreq_value(pinned_cpu, "scaling_min_freq"),
            "scaling_max_freq_khz": cpufreq_value(pinned_cpu, "scaling_max_freq"),
            "scaling_cur_freq_khz_at_start": cpufreq_value(pinned_cpu, "scaling_cur_freq"),
            "git_commit": command_output(["git", "rev-parse", "HEAD"]),
            "tracked_worktree_dirty": bool(git_status),
            "benchmark_path": str(arguments.benchmark),
            "benchmark_sha256": benchmark_digest(benchmark),
        },
        "results": [],
    }

    total_cases = len(arguments.sizes) * len(arguments.tags) * len(arguments.operations)
    case_index = 0
    for message_size in arguments.sizes:
        for tag_bits in arguments.tags:
            for operation in arguments.operations:
                case_index += 1
                case_samples = (
                    arguments.large_samples
                    if message_size >= arguments.large_threshold
                    else arguments.samples
                )
                print(
                    f"case={case_index}/{total_cases} operation={operation} "
                    f"tag_bits={tag_bits} message_bytes={message_size} samples={case_samples}",
                    file=sys.stderr,
                    flush=True,
                )
                parsed = execute_case(
                    benchmark,
                    operation=operation,
                    tag_bits=tag_bits,
                    message_size=message_size,
                    samples=case_samples,
                    target_ms=arguments.target_ms,
                    maximum_iterations=arguments.max_iterations,
                    pinned_cpu=pinned_cpu,
                    timeout_seconds=arguments.timeout_seconds,
                )
                if arguments.require_tsc and parsed.get("tsc_available") is not True:
                    raise RuntimeError("TSC measurement was required but is unavailable")
                record["results"].append(parsed)

    record["environment"]["scaling_cur_freq_khz_at_end"] = cpufreq_value(
        pinned_cpu, "scaling_cur_freq"
    )
    record["environment"]["completed_utc"] = utc_now()
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = arguments.output.with_name(arguments.output.name + ".tmp")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(arguments.output)
    print(f"wrote {len(record['results'])} cases to {arguments.output}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
