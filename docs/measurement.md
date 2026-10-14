# ICMP measurement

The offline harness compares ordinary IPv4 ICMP and Pingo captures. It opens no
network sockets and needs no keys. Install the optional parser and run it from Python:

```sh
python -m pip install -e '.[research]'
python -m pingo.measure examples/measurement-manifest.json --output measurement-output/baseline.json
```

The installed command is `pingo-measure`. Create `measurement-output` before writing
there. The manifest example refers to captures you collect; it contains no sample results.

## Collect comparable runs

Use peers and networks you administer. Record ordinary ping and Pingo under the
same network, operating system, capture interface, and duration. Include Windows
and Linux, different ping implementations and payload sizes, idle Pingo, messages,
file transfers, and VPN traffic. Keep each workload as a separately identified capture.
Include varied ordinary ICMP as negative controls; a single default ping pattern
does not represent all ordinary traffic.

[Wireshark/tshark](https://www.wireshark.org/docs/man-pages/tshark.html) can write
PCAP or PCAPNG on either platform. For example, replace
the interface and documentation addresses with your real peer pair:

```sh
tshark -i "<interface>" -f "icmp and host 192.0.2.10 and host 192.0.2.20" -a duration:60 -w captures/linux-ping-train.pcapng
```

In another terminal run ordinary ping, or run the desired Pingo workload with
the normal CLI/GUI. Capture the complete packets, including both directions.
Use a fresh capture for each independent run. A single observation point avoids
clock differences when measuring echo RTT. Store captures privately; they can contain
endpoint addresses and ordinary plaintext payloads. PCAP files, `captures/`, and
`measurement-output/` are ignored by Git.

Preassign independent runs to training and test sets. Keep every file from one
session in the same set; merge fragments of a run into one capture before analysis.
The harness requires unique capture contents and one capture per session group.
Each system represented in a split must have both labels. Both splits must contain
ordinary and Pingo captures. Use many independent runs: one held-out capture per
condition gives very weak statistical evidence.

## Manifest

Paths are relative to the manifest. Each entry needs:

| Field | Meaning |
| --- | --- |
| `id` | Unique run name; appears in the aggregate report |
| `path` | PCAP or PCAPNG file |
| `label` | `ordinary` or `pingo` |
| `system` | Operating system/environment used for the matched comparison |
| `split` | `train` or `test`, decided before evaluating results |
| `group` | Unique independent session/run identity |
| `endpoints` | Optional two IPv4 addresses to exclude unrelated ICMP |
| `application` | Optional separately measured goodput and application latency |

For application measurements, supply positive `delivered_bytes` and
`elapsed_seconds`, and optional `latency_ms` samples. Use verified delivered bytes
and application acknowledgments to measure these. These operator-supplied values
are explicitly separated from capture-derived echo RTT.

The parser accepts unfragmented IPv4 ICMP, excludes unrelated protocols/endpoints,
and reports exclusions. Truncated packets are rejected. Each capture is limited to
512 MiB on disk and 100,000 matching packets / 128 MiB of ICMP. Use shorter captures
instead of silently truncating the input.

## Read the report

Detection is evaluated per complete held-out capture. A standardized nearest-centroid
baseline learns size, entropy, request timing, traffic rate, echo-request proportion,
and identifier diversity from training captures only. A separate signature detector
checks the visible Pingo markers and ICMP identifier. Labels, filenames, addresses,
and operating-system names are not classifier features.

Reports include confusion counts, accuracy, balanced accuracy, true-positive rate,
false-positive rate, and 95% Wilson intervals, overall and by system. An unavailable
rate is `null`, not zero. Intervals assume independent runs. The report includes
capture hashes for reproducibility and aggregate features; it omits raw payloads
and endpoint addresses. Do not tune parameters on the held-out set.

`ip_bytes_per_second` counts IPv4 bytes, not application goodput. Echo RTT matches
ICMP requests and replies using endpoints, identifier, sequence, and payload digest.
Ambiguous duplicate requests do not yield an RTT sample. A kernel echo reply does
not prove application receipt; Pingo uses separate encrypted acknowledgments.

## Optional offline experiments

```sh
python -m pingo.measure examples/measurement-manifest.json --output measurement-output/experiments.json --experiment distribution --experiment padding --experiment jitter --padding-bucket 128 --max-delay-ms 100 --seed 42
```

| Experiment | What changes in the model |
| --- | --- |
| `distribution` | Reversibly maps ciphertext bits through a prefix tree learned from ordinary **training** payload byte frequencies; adds a four-byte length prefix |
| `padding` | Wraps the original packet with its length and zero padding to the next requested size bucket |
| `jitter` | Adds bounded delays while preserving observed packet order |

Representation experiments verify byte-exact recovery of the original encrypted
packet; the original AEAD tags and authenticated header remain intact. The prefix
tree produces dyadic approximations to symbol probabilities. It does not reproduce
syntax, semantics, or complete traffic distributions. The framing and expansion are
themselves observable. Its learned alphabet needs at least two byte values.

Each experiment reports size overhead, modeled added delay, and packets exceeding
the current 1,200-byte carrier limit. A fixed baseline detector and a detector
retrained on transformed **training** captures both evaluate transformed held-out
captures. Ordinary controls remain unchanged. This accounts for a detector adapting
to a representation change; a reduction against only the old detector is weak evidence.

These are offline hypotheses. They do not model retransmission, congestion, feedback,
or real application latency, and they are not options in the deployed transport.
The unchanged ICMP identifier can still identify a transformed capture. Use the
measurements to decide whether a bounded, authenticated wire extension is justified.
No result from these two detectors establishes undetectability.
