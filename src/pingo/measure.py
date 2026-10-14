"""Offline ICMP capture comparison with explicit independent train/test groups."""

import argparse
import hashlib
import ipaddress
import json
import math
import os
import random
import stat
import statistics
import struct
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .crypto import MAX_WIRE
from .experiments import DistributionCodec, transform

MARKERS = (b"PG01", b"PG02", b"PGH1", b"PGH2", b"PGN1", b"PGN2")
FEATURES = (
    "mean_ip_bytes",
    "std_ip_bytes",
    "mean_payload_entropy",
    "payload_entropy",
    "median_request_gap_ms",
    "p95_request_gap_ms",
    "std_request_gap_ms",
    "echo_request_fraction",
    "ip_bytes_per_second",
    "unique_id_fraction",
)


@dataclass(frozen=True)
class Packet:
    timestamp: float
    source: str
    destination: str
    kind: int
    identifier: int | None
    sequence: int | None
    payload: bytes
    size: int


@dataclass(frozen=True)
class Capture:
    id: str
    path: Path
    label: str
    system: str
    split: str
    group: str
    sha256: str
    endpoints: tuple[str, ...]
    application: dict


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(path):
    path = Path(path).resolve()
    if path.stat().st_size > 1024 * 1024:
        raise ValueError("capture manifest exceeds 1 MiB")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("capture manifest must be an object")
    entries = document.get("captures", [])
    if (
        document.get("version") != 1
        or not isinstance(entries, list)
        or not 4 <= len(entries) <= 500
    ):
        raise ValueError("manifest version must be 1, with 4..500 captures")
    captures, ids, paths, digests, groups = [], set(), set(), set(), {}
    for entry in entries:
        required = ("id", "path", "label", "system", "split", "group")
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(key), str) or not entry[key].strip() for key in required
        ):
            raise ValueError("each capture needs id, path, label, system, split, and group")
        if entry["label"] not in ("ordinary", "pingo") or entry["split"] not in ("train", "test"):
            raise ValueError("capture label is ordinary/pingo and split is train/test")
        source = (path.parent / entry["path"]).resolve()
        metadata = source.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("capture must be a regular file")
        if metadata.st_size > 512 * 1024 * 1024:
            raise ValueError("capture exceeds 512 MiB; use a shorter capture")
        digest = file_hash(source)
        if entry["id"] in ids or source in paths or digest in digests:
            raise ValueError("capture ids, paths, and file contents must be unique")
        group = entry["group"]
        if group in groups:
            raise ValueError("use one capture per independent session group; groups must be unique")
        groups[group] = entry["split"]
        endpoints = tuple(entry.get("endpoints", []))
        if endpoints and len(endpoints) != 2:
            raise ValueError("endpoints must contain exactly two IPv4 addresses")
        endpoints = tuple(str(ipaddress.IPv4Address(value)) for value in endpoints)
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("capture endpoints must be different")
        application = entry.get("application", {})
        if not isinstance(application, dict):
            raise ValueError("application measurements must be an object")
        if application:
            for key in ("delivered_bytes", "elapsed_seconds"):
                value = application.get(key)
                if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                    raise ValueError(
                        "application needs positive delivered_bytes and elapsed_seconds"
                    )
            latency = application.get("latency_ms", [])
            if not isinstance(latency, list) or any(
                not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0 for v in latency
            ):
                raise ValueError("application latency_ms must contain finite nonnegative numbers")
        captures.append(
            Capture(
                entry["id"],
                source,
                entry["label"],
                entry["system"],
                entry["split"],
                group,
                digest,
                endpoints,
                application,
            )
        )
        ids.add(entry["id"])
        paths.add(source)
        digests.add(digest)
    for split in ("train", "test"):
        if {c.label for c in captures if c.split == split} != {"ordinary", "pingo"}:
            raise ValueError("both train and test must contain ordinary and Pingo captures")
        for system in {c.system for c in captures if c.split == split}:
            if {c.label for c in captures if c.split == split and c.system == system} != {
                "ordinary",
                "pingo",
            }:
                raise ValueError("each system in a split needs both ordinary and Pingo captures")
    return captures


def read_packets(capture):
    try:
        from scapy.error import Scapy_Exception

        # Register common capture link types without opening any network socket.
        from scapy.layers import l2  # noqa: F401
        from scapy.layers.inet import IP
        from scapy.utils import PcapReader
    except ImportError as exc:
        raise ValueError(
            'Install capture support: python -m pip install "pingo-tunnel[research]"'
        ) from exc
    try:
        if capture.sha256 and file_hash(capture.path) != capture.sha256:
            raise ValueError(f"{capture.id}: capture changed; finish capturing before analysis")
        result = _read_packets(capture, IP, PcapReader)
        if capture.sha256 and file_hash(capture.path) != capture.sha256:
            raise ValueError(f"{capture.id}: capture changed during analysis")
        return result
    except (Scapy_Exception, EOFError, struct.error) as exc:
        raise ValueError(f"{capture.id}: unsupported or malformed PCAP/PCAPNG capture") from exc


def _read_packets(capture, ip_layer, reader_class):
    packets, total_bytes, excluded = [], 0, Counter()
    with reader_class(str(capture.path)) as reader:
        for raw in reader:
            if ip_layer not in raw or raw[ip_layer].proto != 1:
                excluded["non_ipv4_icmp"] += 1
                continue
            ip = raw[ip_layer]
            if capture.endpoints and {ip.src, ip.dst} != set(capture.endpoints):
                excluded["other_endpoints"] += 1
                continue
            if ip.frag or ip.flags.MF:
                excluded["fragmented"] += 1
                continue
            size, header = int(ip.len), int(ip.ihl) * 4
            frame = bytes(ip)
            if header < 20 or size < header + 8 or len(frame) < size:
                raise ValueError(f"{capture.id}: truncated or malformed IPv4/ICMP packet")
            icmp = frame[header:size]
            kind = icmp[0]
            echo = kind in (0, 8) and icmp[1] == 0
            timestamp = float(raw.time)
            if not math.isfinite(timestamp) or timestamp < 0:
                raise ValueError(f"{capture.id}: invalid packet timestamp")
            packets.append(
                Packet(
                    timestamp,
                    ip.src,
                    ip.dst,
                    kind,
                    int.from_bytes(icmp[4:6], "big") if echo else None,
                    int.from_bytes(icmp[6:8], "big") if echo else None,
                    icmp[8:],
                    size,
                )
            )
            total_bytes += size
            if len(packets) > 100000 or total_bytes > 128 * 1024 * 1024:
                raise ValueError(
                    f"{capture.id}: capture exceeds 100,000 packets or 128 MiB of ICMP"
                )
    if len(packets) < 2:
        raise ValueError(f"{capture.id}: at least two matching ICMP packets are required")
    reordered = sum(a.timestamp > b.timestamp for a, b in zip(packets, packets[1:], strict=False))
    packets.sort(key=lambda p: p.timestamp)
    if packets[-1].timestamp <= packets[0].timestamp:
        raise ValueError(f"{capture.id}: capture must span a positive time interval")
    return packets, {"excluded": dict(excluded), "out_of_order_timestamps": reordered}


def entropy(counts):
    total = sum(counts.values())
    return -sum((n / total) * math.log2(n / total) for n in counts.values()) if total else 0.0


def percentile(values, proportion):
    if not values:
        return None
    values = sorted(values)
    index = (len(values) - 1) * proportion
    left = int(index)
    return values[left] + (values[min(left + 1, len(values) - 1)] - values[left]) * (index - left)


def rtts(packets):
    pending, samples = {}, []
    for packet in packets:
        if packet.identifier is None:
            continue
        digest = hashlib.sha256(packet.payload).digest()
        if packet.kind == 8:
            key = (packet.source, packet.destination, packet.identifier, packet.sequence, digest)
            # A duplicate request makes the reply's RTT ambiguous (Karn's rule).
            if key in pending:
                pending[key] = None
            else:
                pending[key] = packet.timestamp
        elif packet.kind == 0:
            key = (packet.destination, packet.source, packet.identifier, packet.sequence, digest)
            sent = pending.pop(key, None)
            if sent is not None:
                samples.append((packet.timestamp - sent) * 1000)
    return samples


def summary(packets):
    sizes = [p.size for p in packets]
    counts = Counter()
    for packet in packets:
        counts.update(packet.payload)
    request_times = [p.timestamp for p in packets if p.kind == 8 and p.identifier is not None]
    gaps = [(b - a) * 1000 for a, b in zip(request_times, request_times[1:], strict=False)]
    identifiers = [p.identifier for p in packets if p.identifier is not None]
    span = packets[-1].timestamp - packets[0].timestamp
    echo_rtts = rtts(packets)
    features = {
        "mean_ip_bytes": statistics.mean(sizes),
        "std_ip_bytes": statistics.pstdev(sizes),
        "mean_payload_entropy": statistics.mean(entropy(Counter(p.payload)) for p in packets),
        "payload_entropy": entropy(counts),
        "median_request_gap_ms": percentile(gaps, 0.5) or 0,
        "p95_request_gap_ms": percentile(gaps, 0.95) or 0,
        "std_request_gap_ms": statistics.pstdev(gaps) if gaps else 0,
        "echo_request_fraction": len(request_times) / len(packets),
        "ip_bytes_per_second": sum(sizes) / span,
        "unique_id_fraction": len(set(identifiers)) / len(identifiers) if identifiers else 0,
    }
    return {
        "packets": len(packets),
        "duration_seconds": span,
        "ip_bytes": sum(sizes),
        "features": features,
        "payload_size_histogram": dict(sorted(Counter(len(p.payload) for p in packets).items())),
        "echo_rtt_ms": {
            "samples": len(echo_rtts),
            "median": percentile(echo_rtts, 0.5),
            "p95": percentile(echo_rtts, 0.95),
        },
        "signature_detected": any(
            p.identifier == 0x5047 or p.payload.startswith(MARKERS) for p in packets
        ),
        "exceeds_pingo_payload_limit": sum(len(p.payload) > MAX_WIRE for p in packets),
    }


class CentroidDetector:
    """Standardized nearest centroids fitted only on training captures."""

    def __init__(self, training):
        self.mean, self.scale = {}, {}
        for name in FEATURES:
            values = [row["features"][name] for row in training]
            self.mean[name] = statistics.mean(values)
            self.scale[name] = max(statistics.pstdev(values), 1e-9)
        self.centroids = {}
        for label in ("ordinary", "pingo"):
            vectors = [self.vector(row) for row in training if row["label"] == label]
            self.centroids[label] = [
                statistics.mean(values) for values in zip(*vectors, strict=True)
            ]

    def vector(self, row):
        return [(row["features"][name] - self.mean[name]) / self.scale[name] for name in FEATURES]

    def predict(self, row):
        vector = self.vector(row)
        return (
            min(
                self.centroids,
                key=lambda label: sum(
                    (a - b) ** 2 for a, b in zip(vector, self.centroids[label], strict=True)
                ),
            )
            == "pingo"
        )


def wilson(successes, total):
    if not total:
        return None
    z, rate = 1.959963984540054, successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    margin = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return [max(0, center - margin), min(1, center + margin)]


def classification(rows, predict):
    tp = fp = tn = fn = 0
    for row in rows:
        positive = predict(row)
        if row["label"] == "pingo":
            tp += positive
            fn += not positive
        else:
            fp += positive
            tn += not positive
    tpr, fpr = tp / (tp + fn) if tp + fn else None, fp / (fp + tn) if fp + tn else None
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": (tp + tn) / len(rows) if rows else None,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "balanced_accuracy": (tpr + 1 - fpr) / 2 if tpr is not None and fpr is not None else None,
        "tpr_95_percent_interval": wilson(tp, tp + fn),
        "fpr_95_percent_interval": wilson(fp, fp + tn),
    }


def evaluation(rows, detector):
    held_out = [row for row in rows if row["split"] == "test"]
    predictors = {
        "statistical": detector.predict,
        "signature": lambda row: row["signature_detected"],
    }
    return {
        name: {
            "overall": classification(held_out, predict),
            "by_system": {
                system: classification(
                    [row for row in held_out if row["system"] == system], predict
                )
                for system in sorted({row["system"] for row in held_out})
            },
        }
        for name, predict in predictors.items()
    }


def analyze(manifest, strategies=(), bucket=128, max_delay_ms=100, seed=0):
    if any(s not in ("distribution", "padding", "jitter") for s in strategies):
        raise ValueError("unknown experiment")
    if not 32 <= bucket <= MAX_WIRE or not 0 <= max_delay_ms <= 1000:
        raise ValueError("padding bucket is 32..1200; modeled delay is 0..1000 ms")
    captures = load_manifest(manifest)
    codec = None
    cover_counts = Counter()
    if "distribution" in strategies:
        for capture in captures:
            if capture.split == "train" and capture.label == "ordinary":
                packets, _ = read_packets(capture)
                for packet in packets:
                    cover_counts.update(packet.payload)
        codec = DistributionCodec(cover_counts)
    rows = []
    variants = {strategy: [] for strategy in dict.fromkeys(strategies)}
    for capture in captures:
        packets, metadata = read_packets(capture)
        info = {
            "id": capture.id,
            "label": capture.label,
            "system": capture.system,
            "split": capture.split,
            "group": capture.group,
            "capture_sha256": capture.sha256,
        }
        row = {**info, **summary(packets), **metadata}
        app = capture.application
        if app:
            row["application"] = {
                "delivered_bytes_per_second": app["delivered_bytes"] / app["elapsed_seconds"],
                "latency_ms": {
                    "samples": len(app.get("latency_ms", [])),
                    "median": percentile(app.get("latency_ms", []), 0.5),
                    "p95": percentile(app.get("latency_ms", []), 0.95),
                },
                "source": "operator-supplied measurements",
            }
        rows.append(row)
        for strategy, variant in variants.items():
            if capture.label != "pingo":
                variant.append(row)
                continue
            modeled, delays = transform(
                packets,
                strategy,
                random.Random(f"{seed}:{capture.id}:{strategy}"),
                codec,
                bucket,
                max_delay_ms,
            )
            changed = {
                **info,
                **summary(modeled),
                "ip_byte_overhead_ratio": sum(p.size for p in modeled) / row["ip_bytes"],
                "added_delay_ms": {
                    "mean": statistics.mean(delays),
                    "p95": percentile(delays, 0.95),
                },
            }
            variant.append(changed)
    detector = CentroidDetector([row for row in rows if row["split"] == "train"])
    results = {}
    for strategy, variant in variants.items():
        retrained = CentroidDetector([row for row in variant if row["split"] == "train"])
        results[strategy] = {
            "fixed_detector": evaluation(variant, detector),
            "retrained_detector": evaluation(variant, retrained),
            "captures": variant,
        }
    return {
        "version": 1,
        "pingo_version": __version__,
        "unit_of_detection": "whole capture",
        "feature_names": list(FEATURES),
        "baseline": {"detectors": evaluation(rows, detector), "captures": rows},
        "experiments": results,
        "parameters": {
            "seed": seed,
            "padding_bucket_bytes": bucket,
            "max_modeled_delay_ms": max_delay_ms,
            "distribution_cover_bytes": sum(cover_counts.values()),
            "distribution_cover_symbols": len(cover_counts),
        },
        "limits": [
            "Echo RTT measures ICMP request/reply timing, not application delivery latency.",
            "Offline experiments do not model congestion, retransmissions, or network feedback.",
            "Distribution encoding approximates byte frequencies, not syntax or behavior.",
            "Exceeding 1200 payload bytes prevents use with the current Pingo transport.",
            "Results apply to these captures and detectors; they do not establish undetectability.",
            "Confidence intervals assume independent capture groups; correlated runs weaken them.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare ICMP captures and offline Pingo experiments"
    )
    parser.add_argument(
        "manifest", type=Path, help="capture manifest with independent train/test groups"
    )
    parser.add_argument("--output", type=Path, help="write the aggregate JSON report")
    parser.add_argument(
        "--experiment", action="append", default=[], choices=("distribution", "padding", "jitter")
    )
    parser.add_argument("--padding-bucket", type=int, default=128, metavar="BYTES")
    parser.add_argument("--max-delay-ms", type=float, default=100)
    parser.add_argument("--seed", type=int, default=0, help="reproducible offline experiment seed")
    args = parser.parse_args(argv)
    try:
        if args.output:
            inputs = {c.path for c in load_manifest(args.manifest)} | {args.manifest.resolve()}
            if args.output.resolve() in inputs or (
                args.output.exists() and any(args.output.samefile(source) for source in inputs)
            ):
                raise ValueError("report output cannot overwrite a manifest or capture")
        report = analyze(
            args.manifest, args.experiment, args.padding_bucket, args.max_delay_ms, args.seed
        )
        encoded = json.dumps(report, indent=2, allow_nan=False) + "\n"
        if args.output:
            # Replacing a new inode preserves inputs even if output is a hardlink alias.
            fd, temporary = tempfile.mkstemp(prefix=".pingo-report-", dir=args.output.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, args.output)
            finally:
                Path(temporary).unlink(missing_ok=True)
            print(f"Wrote {args.output}")
        else:
            print(encoded, end="")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Measurement failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
