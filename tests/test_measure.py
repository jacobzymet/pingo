import json
import random
from collections import Counter

import pytest

from pingo.crypto import PacketError, Session
from pingo.experiments import DistributionCodec, pad, unpad
from pingo.measure import Capture, analyze, load_manifest, main, read_packets, summary

scapy = pytest.importorskip("scapy.all")


def write_capture(path, label, start=0, identifier=None, pcapng=False):
    rng = random.Random(start)
    writer = (scapy.PcapNgWriter if pcapng else scapy.PcapWriter)(str(path))
    try:
        for index in range(12):
            payload = (
                b"abcdefghijklmnop" * 3
                if label == "ordinary"
                else (b"PG02" + rng.randbytes(80 + 70 * (index % 3)))
            )
            interval = 1 if label == "ordinary" else 0.05
            for reply in (False, True):
                packet = (
                    scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                    / scapy.IP(
                        src="192.0.2.20" if reply else "192.0.2.10",
                        dst="192.0.2.10" if reply else "192.0.2.20",
                    )
                    / scapy.ICMP(
                        type=0 if reply else 8,
                        id=identifier
                        if identifier is not None
                        else (17 if label == "ordinary" else 0x5047),
                        seq=index,
                    )
                    / scapy.Raw(payload)
                )
                packet.time = start + index * interval + (0.01 if reply else 0)
                writer.write(packet)
    finally:
        writer.close()


@pytest.fixture
def manifest(tmp_path):
    captures = []
    for system in ("linux", "windows"):
        for split in ("train", "test"):
            for label in ("ordinary", "pingo"):
                id = f"{system}-{split}-{label}"
                source = tmp_path / f"{id}.pcap"
                write_capture(source, label, start=100 + len(captures) * 100)
                captures.append(
                    {
                        "id": id,
                        "path": source.name,
                        "label": label,
                        "system": system,
                        "split": split,
                        "group": id,
                        "endpoints": ["192.0.2.10", "192.0.2.20"],
                    }
                )
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({"version": 1, "captures": captures}), encoding="utf-8")
    return path


def test_held_out_detection_rates_bandwidth_latency_and_systems(manifest):
    report = analyze(manifest)
    detectors = report["baseline"]["detectors"]
    for detector in detectors.values():
        rates = detector["overall"]
        assert rates["accuracy"] == rates["true_positive_rate"] == 1
        assert rates["false_positive_rate"] == 0
        assert rates["tp"] == rates["tn"] == 2
        assert rates["fpr_95_percent_interval"][1] > 0  # zero observed FPs is not certainty
        assert set(detector["by_system"]) == {"linux", "windows"}
    captures = report["baseline"]["captures"]
    assert all(c["echo_rtt_ms"]["samples"] == 12 for c in captures)
    assert all(c["echo_rtt_ms"]["median"] == pytest.approx(10) for c in captures)
    assert all(c["features"]["ip_bytes_per_second"] > 0 for c in captures)
    assert "192.0.2.10" not in json.dumps(report)
    assert str(manifest.parent) not in json.dumps(report)


@pytest.mark.parametrize("input_kind", ["manifest", "capture"])
def test_report_cannot_overwrite_input_through_a_hardlink(manifest, input_kind, capsys):
    source = manifest if input_kind == "manifest" else load_manifest(manifest)[0].path
    original = source.read_bytes()
    output = manifest.parent / "report.json"
    output.hardlink_to(source)
    assert main([str(manifest), "--output", str(output)]) == 2
    assert "cannot overwrite" in capsys.readouterr().err
    assert source.read_bytes() == original


def test_changed_capture_is_rejected_before_analysis(manifest):
    capture = load_manifest(manifest)[0]
    write_capture(capture.path, "ordinary", start=12345)
    with pytest.raises(ValueError, match="capture changed"):
        read_packets(capture)


def test_capture_changed_while_reading_is_rejected(manifest, monkeypatch):
    from pingo import measure

    capture = load_manifest(manifest)[0]
    original = measure._read_packets

    def changed(*args):
        result = original(*args)
        write_capture(capture.path, "ordinary", start=12345)
        return result

    monkeypatch.setattr(measure, "_read_packets", changed)
    with pytest.raises(ValueError, match="capture changed during"):
        read_packets(capture)


def test_experiments_are_reproducible_and_evaluate_retrained_detectors(manifest):
    names = ("distribution", "padding", "jitter")
    first = analyze(manifest, names, bucket=1200, max_delay_ms=80, seed=42)
    assert first == analyze(manifest, names, bucket=1200, max_delay_ms=80, seed=42)
    assert set(first["experiments"]) == set(names)
    for experiment in first["experiments"].values():
        assert "fixed_detector" in experiment and "retrained_detector" in experiment
        # Encoding and timing cannot remove the visible ICMP identifier.
        assert experiment["retrained_detector"]["signature"]["overall"]["true_positive_rate"] == 1
    assert first["parameters"]["distribution_cover_bytes"] == 2 * 24 * 48
    assert first["parameters"]["distribution_cover_symbols"] == 16
    shaped = [c for c in first["experiments"]["jitter"]["captures"] if c["label"] == "pingo"]
    assert all(0 <= c["added_delay_ms"]["mean"] <= 80 for c in shaped)
    padded = [c for c in first["experiments"]["padding"]["captures"] if c["label"] == "pingo"]
    assert all(c["ip_byte_overhead_ratio"] > 1 for c in padded)


def test_signature_false_positives_are_reported(manifest):
    document = json.loads(manifest.read_text())
    row = next(c for c in document["captures"] if c["split"] == "test" and c["label"] == "ordinary")
    write_capture(manifest.parent / row["path"], "ordinary", 2000, identifier=0x5047)
    report = analyze(manifest)
    rates = report["baseline"]["detectors"]["signature"]["overall"]
    assert rates["fp"] == 1 and rates["false_positive_rate"] == 0.5


def test_invalid_capture_has_an_actionable_cli_error(manifest, capsys):
    document = json.loads(manifest.read_text())
    path = manifest.parent / document["captures"][0]["path"]
    path.write_bytes(b"not a packet capture")
    assert main([str(manifest)]) == 2
    assert "unsupported or malformed" in capsys.readouterr().err


@pytest.mark.parametrize("problem", ["group", "duplicate", "missing_class", "confounded_system"])
def test_leakage_and_confounded_datasets_are_rejected(manifest, problem):
    document = json.loads(manifest.read_text())
    rows = document["captures"]
    if problem == "group":
        rows[2]["group"] = rows[0]["group"]
    elif problem == "duplicate":
        (manifest.parent / rows[2]["path"]).write_bytes(
            (manifest.parent / rows[0]["path"]).read_bytes()
        )
    elif problem == "missing_class":
        for row in rows:
            if row["split"] == "test":
                row["label"] = "ordinary"
    else:
        rows[0]["system"] = "other-platform"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        load_manifest(manifest)


def test_pcapng_and_missing_echo_replies_have_correct_latency(tmp_path):
    path = tmp_path / "sample.pcapng"
    write_capture(path, "ordinary", start=20, pcapng=True)
    capture = Capture("sample", path, "ordinary", "linux", "test", "sample", "", (), {})
    packets, _ = read_packets(capture)
    assert summary(packets)["echo_rtt_ms"]["samples"] == 12
    requests = [p for p in packets if p.kind == 8]
    assert summary(requests)["echo_rtt_ms"] == {"samples": 0, "median": None, "p95": None}
    duplicated = sorted(packets + [packets[0]], key=lambda p: p.timestamp)
    assert summary(duplicated)["echo_rtt_ms"]["samples"] == 11


def test_distribution_encoding_preserves_authenticated_ciphertext():
    codec = DistributionCodec(Counter(b"aaaaaaaabbbbccde"))
    outgoing, incoming, transcript = b"a" * 32, b"b" * 32, b"c" * 32
    sender = Session(outgoing, incoming, transcript)
    receiver = Session(incoming, outgoing, transcript)
    encrypted = sender.encrypt(b"authenticated application data")
    encoded = codec.encode(encrypted)
    assert receiver.decrypt(codec.decode(encoded)) == b"authenticated application data"
    corrupt = bytearray(sender.encrypt(b"tamper"))
    corrupt[-1] ^= 1
    with pytest.raises(PacketError):
        receiver.decrypt(codec.decode(codec.encode(bytes(corrupt))))
    for data in (b"", bytes(range(256)), random.Random(8).randbytes(1200)):
        assert codec.decode(codec.encode(data)) == data
    with pytest.raises(ValueError):
        codec.decode(encoded + b"a")
    with pytest.raises(ValueError):
        codec.decode(bytes(3))
    with pytest.raises(ValueError):
        DistributionCodec({65: 1})


def test_padding_round_trip_and_invalid_frames():
    for data in (b"", b"ciphertext", bytes(1200)):
        encoded = pad(data, 128)
        assert len(encoded) % 128 == 0 and unpad(encoded) == data
    assert len(pad(bytes(1200), 128)) > 1200
    with pytest.raises(ValueError):
        unpad((1201).to_bytes(4, "big") + bytes(1201))
    with pytest.raises(ValueError):
        unpad(pad(b"abc", 32)[:-1] + b"x")


def test_application_metrics_are_separate_and_report_cannot_overwrite_inputs(manifest, capsys):
    document = json.loads(manifest.read_text())
    document["captures"][1]["application"] = {
        "delivered_bytes": 4096,
        "elapsed_seconds": 2,
        "latency_ms": [12, 16, 20],
    }
    manifest.write_text(json.dumps(document), encoding="utf-8")
    report = analyze(manifest)
    supplied = report["baseline"]["captures"][1]["application"]
    assert supplied["delivered_bytes_per_second"] == 2048
    assert supplied["latency_ms"]["median"] == 16
    before = manifest.read_bytes()
    assert main([str(manifest), "--output", str(manifest)]) == 2
    assert manifest.read_bytes() == before
    output = manifest.parent / "report.json"
    assert main([str(manifest), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["baseline"]["detectors"]
    assert "cannot overwrite" in capsys.readouterr().err
