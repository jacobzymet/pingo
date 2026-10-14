# Pingo

Pingo is an experimental Python application for encrypted, authenticated communication over
IPv4 ICMP. One shared transport powers reliable messages/file transfers and a
Linux TUN or Windows Wintun VPN. Two configured peers share one random 32-byte key.

ICMP does not provide reliable delivery. Packet ordering, retransmission, and
connection management must be implemented above it.
Pingo's direct mode supplies fragment ordering/reassembly, stop-and-wait
acknowledgments, bounded retries, and duplicate suppression. Both modes use
authenticated session setup, keepalives, and inactivity timeouts. VPN delivery
is best-effort: inner TCP or applications handle loss and ordering. VPN datagrams
use an adaptive congestion window and pacing; direct transfers use RTT-based
timeouts and exponential backoff. Connections recover with bounded retries, and
files resume from durable checkpoints across sessions and process restarts.

Use Pingo on networks you administer. Both endpoints need directly reachable IPv4
addresses and inbound ICMP echo requests allowed from the other peer.

| Mode | Platforms | Requirements |
| --- | --- | --- |
| Messages and files | Windows and Linux | Raw ICMP permissions and a shared key |
| Linux IPv4 VPN | Linux | TUN, iproute2; nftables for the kill switch; systemd-resolved for DNS |
| Windows IPv4 VPN | Windows | Signed official Wintun DLL; Administrator permissions |

IPv6, NAT traversal, and multiple peers are unsupported.

## Desktop app

Pingo now has a local HTML/CSS/JavaScript interface in a native desktop window.
The existing CLI and full packet hex dumps remain available. The desktop includes
saved connections, native file pickers, shared-key generation, matching peer setup
export, messages, resumable file progress, VPN controls, setup checks, and recovery.

On Windows, open **`Start Pingo.cmd`** from this checkout. It uses the portable
build if present; otherwise it sets up the Python environment and desktop dependencies.
The first source launch needs Python 3.11+ and Internet access for installation.
For an existing environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[gui]"
.\.venv\Scripts\python.exe -m pingo gui
```

The Windows desktop uses Microsoft Edge WebView2 Runtime; install the official
[WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/)
if it is missing. The interface and fonts are local; no website, CDN, or browser
tab is needed. The native bridge exposes fixed actions, not arbitrary commands.

1. Choose **Add a connection**. Enter the other computer's reachable IPv4 address.
   Enter this computer's IPv4 too if you want to export matching peer setup;
   detected addresses are suggestions, not reachability guarantees.
2. Generate a key on **one computer only**, or select your existing shared key.
   **Set up other computer** writes a new folder containing `peer.toml`, `peer.key`,
   and instructions. Transfer that folder privately through a separate trusted
   channel, then choose **Import** on the other computer.
3. Run **Settings → Run setup check**. Allow inbound ICMP echo requests
   from each peer on both computers. Local checks do not prove the peer is reachable.
4. Use **Reopen as Administrator** for network actions on Windows. Open the **Receive**
   tab and start receiving on one computer, then use **Message** or **File** on the other. Stop before switching
   tasks. The desktop enforces one activity per window; run only one Pingo instance
   per endpoint/key, including CLI processes.

VPN has its own screen with client/responder roles, tunnel addresses, a Wintun
file picker on Windows, and expandable route, DNS, source-allowlist, and kill-switch
settings. Default IPv4 routing still requires an explicitly configured exit peer;
see the VPN instructions below. Ordinary stop/window close waits for cleanup.
Failures may retain protection; **Settings → Restore connectivity after a VPN failure → Remove retained protection**
restores ordinary traffic. Hard termination has the same limitations as the CLI.

Use **Ctrl+Enter** to send a message. Drafts and selected files remain when switching
action tabs. The message composer shows its UTF-8 byte count and prevents oversized sends.

Hex is displayed by default. The packet panel can collapse. Pausing freezes the displayed
packets for filtering and hex inspection; it does not pause networking or packet
collection. The interface displays the latest 120 packets; trace exports include
up to 2,000 recent packet/activity records. Export is a bounded snapshot, not an
unlimited capture. Received messages are rendered as text. Keys never appear in
the trace or JavaScript bridge responses; key **paths** are used for file selection.

Connections and generated keys are stored in `%LOCALAPPDATA%\Pingo` on Windows,
or `$XDG_DATA_HOME/pingo` (default `~/.local/share/pingo`) on Linux. Pingo restricts
its storage directory to the current user, SYSTEM and Administrators on Windows,
and mode 0700 on Linux. Protect imported/external keys and custom receive folders
yourself. `pingo gui --data-dir PATH` can select a different storage directory.
On Linux, install a pywebview GTK or Qt backend, for example
`pip install -e '.[gui]' 'pywebview[qt]'`, then launch from a graphical session
with the permissions needed for raw ICMP/TUN.

### Portable Windows build

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build-desktop.ps1
```

Distribute **`dist/Pingo-Windows.zip`**, or the whole `dist/Pingo` folder. Unzip it
and open `Pingo.exe`; recipients do not
need Python. `Pingo-worker.exe` is a companion process and should remain beside
the app. WebView2 Runtime and, for Windows VPN, the signed official Wintun DLL
are separate prerequisites. The build is unsigned. The script bundles the app,
HTML assets, Python runtime and dependencies using PyInstaller.
Use a maintained 64-bit Python environment for release builds, such as Python
3.13.16 or 3.14.8. Pass `-Python PATH` to the build script to select its interpreter.

## Install CLI

Python 3.11 or newer. From the repository on each endpoint:

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pingo --help
```

```sh
# Linux
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m pingo --help
```

Omit `[dev]` for runtime-only installation. Installing also supplies the `pingo`
entry point; examples use the explicit interpreter to avoid activation issues.
Keep the checkout/virtual environment private, particularly when running elevated.

## Configure two peers

Examples below call the real addresses `A_IP` and `B_IP`; replace the example
`192.0.2.*` addresses in both TOML files. Configuration paths for keys and output
directories are relative to the TOML file, not the current working directory.
Use literal IPv4 addresses, not hostnames. Do not use the tunnel's inner address
as the endpoint address.

```powershell
# Peer A
Copy-Item examples/peer-a.toml local-a.toml
.\.venv\Scripts\python.exe -m pingo keygen keys/peer.key
# Peer B
Copy-Item examples/peer-b.toml local-b.toml
```

Linux equivalent: `cp examples/peer-a.toml local-a.toml` (A),
`cp examples/peer-b.toml local-b.toml` (B), and
`.venv/bin/python -m pingo keygen keys/peer.key` (A).

Securely copy **the same** `keys/peer.key` from A to B through a separate trusted
channel. Do not independently generate two keys. Keygen refuses to overwrite an
existing key. Linux key files must have no group/other permissions (`chmod 600`).
On Windows, restrict the key file ACL to your account and the administrative
account running Pingo; Python's POSIX mode does not set a private Windows ACL.
Do not paste keys into shell arguments, source control, or logs. Rotate by
stopping both endpoints and replacing their key files with the same new key.

Raw ICMP requires an elevated Administrator terminal on Windows or root /
`CAP_NET_RAW` on Linux. VPN also needs `CAP_NET_ADMIN`, `/dev/net/tun`, and
`iproute2`. The examples use an elevated terminal or `sudo` rather than granting
capabilities to a general Python interpreter. Linux kill-switch support requires
`nftables`; automatic DNS requires `systemd-resolved` and `resolvectl`. Windows VPN
requires `--wintun-dll` pointing to the signed [official Wintun DLL](https://www.wintun.net/)
matching your Python architecture. Pingo does not download or bundle drivers.

Both firewalls/network paths must permit inbound ICMP **echo requests** (type 8)
from the other configured endpoint. Both peers emit requests independently;
ordinary echo replies (type 0) are ignored. Restrict firewall allowances to the
two endpoint addresses. Router NAT mappings, echo identifiers rewritten by NAT,
ICMP inspection, or rate limits can prevent operation. A successful `ping` alone
does not prove that requests can travel in both directions.

## Messages and files

Start the receiver on B in an elevated PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pingo listen --config local-b.toml
```

Send from A in another elevated terminal:

```powershell
.\.venv\Scripts\python.exe -m pingo message --config local-a.toml "Hello through ICMP"
.\.venv\Scripts\python.exe -m pingo file --config local-a.toml .\example.zip
```

On Linux, substitute `sudo .venv/bin/python` for
`.\.venv\Scripts\python.exe`. To reverse direction, stop B's listener, start
`listen --config local-a.toml` on A, then send using `local-b.toml` on B. Run only
one Pingo process per endpoint/key at a time. Concurrent sender processes are
unsupported; a new confirmed session replaces the receiver's previous session.

The listener prints JSON-escaped message events. Message success means its
receiver callback ran. File success means all bytes matched the declared size
and SHA-256, the receiver flushed/fsynced the temporary file, and created the
final file atomically without overwriting anything. A received filename is
`TRANSFER_ID-sanitized-name`, and the sender prints that filename only after
receiving the completion acknowledgment. Transfers use bounded 32 KiB chunks;
each chunk is fsynced and checkpointed atomically before acknowledgment. Partial
files and completion records survive session changes and process restarts.
Rerun the same file command to resume; the sender verifies the receiver's prefix
hash before continuing. Identical contents with the same filename return the
existing verified file instead of duplicating it.

The listener retains up to 128 resume records for 24 hours (`--resume-retention`
accepts 60–604800 seconds). Expired partials are removed while the listener runs;
completed files remain. Pending files reserve directory quota. Keep the directory
private: checkpoints and partials contain plaintext. `file --no-resume` uses the
legacy format and cleans partials on session change or exit. Upgrade both peers
to version 0.3 or later for the forward-secret handshake, resumable transfers,
and congestion-aware VPNs. Version 0.3 uses wire protocol v2 and does not connect
to older peers. Existing random shared keys and configurations can be reused.

Defaults: messages up to 60,000 UTF-8 bytes, files up to 64 MiB, receive directory
up to 256 MiB and 1,023 entries. `max_file_bytes` and `max_receive_bytes` adjust
the byte limits (maximum 1 GiB/file and 4 GiB/directory). Stored files must be
cleared manually when the quota is full. The directory should be private and not
modified concurrently; it is not a multi-process quota service.

Each reliable fragment is acknowledged after acceptance. The final fragment's
acknowledgment contains the application's result. A lost acknowledgment retries
with a fresh encryption counter; the receiver deduplicates without repeating
the operation. Stop-and-wait limits throughput to roughly one 1,000-byte fragment
per round-trip, before losses. RTT measurements adapt timeouts; losses double
them, bounded to two seconds. `retry_seconds` is the initial/minimum timeout
(0.05–2 seconds); `attempts` accepts 1–20. `--reconnects 0..20` bounds recovery,
default 10, with connection backoff up to ten seconds. Files reconcile persisted
state after reconnecting. Messages are never automatically replayed after an
ambiguous send failure; check the receiver before rerunning a message command.

Monotonic per-session operation IDs prevent delayed requests from executing
again after the 60-second result cache expires. An expired result cannot be
acknowledged again. Message deduplication does not survive a new session;
resumable files also retain their content identity and completion state.

## Live traffic

All network commands emit one flushed JSON record per sent/received Pingo wire
packet on stderr: timestamps, direction, byte counts, cumulative totals,
throughput, and complete encrypted payloads as hex. Handshakes, keepalives,
fragments and acknowledgments are included. VPN commands also emit TUN metadata:
addresses, protocol, congestion window and RTT. Keys and decrypted TUN payloads
are not dumped. Counters are per layer/direction and exclude outer headers.

`--traffic hex` is the default. `--traffic summary` omits hex; `--traffic off`
disables packet output. Records are immediate, without sampling or batching;
a slow terminal or pipe can reduce throughput. Results/messages remain on stdout;
diagnostics share stderr with traffic JSON. Treat captured traces as sensitive.

## IPv4 VPN

The VPN carries IP datagrams through the same authenticated transport. It uses
best-effort delivery, leaving reliability to inner TCP or other applications.
MTU is 1,000 bytes. Authenticated feedback grows the congestion window on delivery
and halves it on loss. Pacing is capped at 200 data packets/second and 64 in flight;
VPN datagrams are not retransmitted. IPv6 packets are
rejected. Peer source addresses default to the TUN subnet; add explicit
`--allowed-source CIDR` values for routed source networks (providing any replaces
that default). A peer holding the shared key is trusted within that allowlist.
Upgrade both peers: the congestion-aware VPN uses handshake mode `C` and refuses
legacy mode `V` instead of mixing incompatible implementations.

Start B as VPN responder (no default route on the exit peer):

```sh
sudo .venv/bin/python -m pingo vpn --config local-b.toml --listen \
  --address 10.77.0.2/30
```

Then A as initiator, initially using just the connected tunnel subnet:

```sh
sudo .venv/bin/python -m pingo vpn --config local-a.toml \
  --address 10.77.0.1/30
# From a separate terminal on A: ping 10.77.0.2
```

For a selected remote network, run A with:

```sh
sudo .venv/bin/python -m pingo vpn --config local-a.toml \
  --address 10.77.0.1/30 --route 192.168.50.0/24 \
  --allowed-source 10.77.0.0/30 --allowed-source 192.168.50.0/24
```

The source allowlist admits replies from that remote network. B must have
forwarding/firewall rules and a return route from that network to `10.77.0.0/30`,
or deliberate NAT. To send default IPv4 traffic from A through B:

```sh
sudo .venv/bin/python -m pingo vpn --config local-a.toml \
  --address 10.77.0.1/30 --default-route --allowed-source 0.0.0.0/0
```

That last command changes A's routing after authentication. It pins B's outer
address to the original gateway/interface before adding `0.0.0.0/1` and
`128.0.0.0/1` through TUN. It refuses existing conflicting routes and custom
policy routing instead of replacing them. Existing more-specific IPv4 routes
(including local LAN routes) still win. Thus it routes **default IPv4 traffic**,
not literally every packet. With `--default-route`, the client kill switch is
enabled automatically and blocks outside traffic, including external IPv6 and
excluded routes. `--kill-switch` also protects selected-route clients;
`--no-kill-switch` opts out. The responder/exit must not enable a client kill switch.

Allowing `0.0.0.0/0` is necessary for Internet replies with arbitrary source
addresses; it trusts B to deliver packets from any IPv4 source. Without expanding
the allowlist, only replies sourced within the TUN subnet are accepted.

**Internet exit setup is explicit and remains the administrator's responsibility.**
Pingo does not change B's forwarding, firewall, NAT, or DNS configuration. For
a dedicated Linux test exit using `iptables`, an example is:

```sh
# On B only. Replace eth0 with B's Internet-facing interface.
# Inspect existing rules and record the previous forwarding value first.
sysctl net.ipv4.ip_forward
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -I FORWARD 1 -i pingo0 -o eth0 -s 10.77.0.0/30 -j ACCEPT
sudo iptables -I FORWARD 1 -i eth0 -o pingo0 -d 10.77.0.0/30 \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 10.77.0.0/30 -o eth0 -j MASQUERADE
```

Undo those exact rules with matching `iptables -D` commands and restore the
previous forwarding value after the test. These are manual changes outside
Pingo's route lifecycle. Existing distribution firewall managers may require a
different setup. B needs a valid Internet route and working DNS for itself.

Default-route clients configure tunnel DNS automatically using `1.1.1.1`, unless
you supply one or more `--dns IPv4` resolvers reachable through B. Resolver /32
routes prevent LAN routes taking precedence. `--no-dns` leaves DNS untouched.
Linux uses `resolvectl` only on the new link; Windows creates an owned catch-all
NRPT rule and refuses existing effective DNS policies. Cleanup reverts/removes
that state. DNS setup errors retain an active kill switch.

Windows VPN uses the same flags in an Administrator PowerShell:

```powershell
# B: responder
.\.venv\Scripts\python.exe -m pingo vpn --config local-b.toml --listen `
  --address 10.77.0.2/30 --wintun-dll C:\Tools\Wintun\wintun.dll
# A: client
.\.venv\Scripts\python.exe -m pingo vpn --config local-a.toml `
  --address 10.77.0.1/30 --wintun-dll C:\Tools\Wintun\wintun.dll
```

Pingo verifies the DLL signature, creates its own adapter, and refuses existing
adapters. Routes use ActiveStore and are journaled for reversal. Windows exit
forwarding/NAT must be configured separately; the Linux iptables example does
not apply to Windows.

Linux protection uses a dedicated atomic nftables table; Windows uses persistent
WFP block filters installed in a transaction. Loopback, IPv4 tunnel traffic and
outer ICMP to the configured peer are permitted. Protection remains throughout
reconnection. Failures and crashes retain protection; normal Ctrl+C/SIGTERM/exit
removes it after DNS/routes cleanup. Restore connectivity after failure with:

```sh
# Linux: exact table identity printed at startup
sudo .venv/bin/python -m pingo unlock --table pingo_<32_hex_digits>
```

```powershell
# Windows: removes only Pingo filters and retained owned DNS policies
.\.venv\Scripts\python.exe -m pingo unlock
```

Do not run a kill-switch client in the same host/network namespace as an exit.
Windows protection covers locally originated traffic, not Windows forwarding.
Existing firewall policy can still block permitted traffic. Administrators can
modify or bypass these protections. Windows hard termination may leave an adapter
or route state requiring manual cleanup.

Pingo removes its own routes in reverse order on normal exit, Ctrl+C, SIGTERM,
setup failure, or exhausted reconnection attempts. Peer inactivity (30 seconds)
triggers recovery while TUN, routing, DNS and protection stay in place.
It closes its nonpersistent TUN,
which removes that interface. It never overwrites pre-existing routes. Cleanup
failures are reported with exact recovery commands. Keep the terminal/log visible.
SIGKILL, a crash, or power loss can bypass cleanup: the TUN routes disappear with
the device, but the added outer peer `/32` route may remain. Record `ip -4 route`
before starting; remove only Pingo's added peer host route if needed. Do not
change routing concurrently while a VPN session runs.

## Security and protocol

* Random 32-byte PSK and the Noise NNpsk0 X25519/ChaChaPoly/SHA256 handshake,
  with fresh ephemeral keys on both peers. The mode and protocol version are bound
  to the transcript. HKDF derives separate directional datagram keys; packets retain
  ChaCha20-Poly1305 with full tags. Later PSK disclosure alone cannot decrypt recorded
  completed sessions when ephemeral/session secrets remain unavailable. Disclosure
  still permits future impersonation; earlier version 0.2 traffic has no forward secrecy.
* A 64-bit packet counter forms a 96-bit nonce with a fixed prefix, under distinct
  session/direction keys. Retries consume new counters. Sessions expire after
  2^32 sent packets and are never saved/restored. Restarts require fresh ephemeral keys.
* Magic/version, session ID, and counter are AEAD associated data. An authenticated
  1,024-packet replay window accepts limited reordering, rejects duplicates, and
  changes only after tag verification. Confirmation is required before adopting
  a responder session; recorded old handshakes cannot reinstate old session keys.
* Explicit peer IPv4 filtering is additional filtering, not authentication. The
  shared key is the identity. Use a different key per peer pair. Handshake attempts
  are bounded to one pending candidate; replayed signed hellos can still cause
  denial of service. Pingo does not defend against a malicious authorized peer.
* Ciphertext payload is at most 1,200 bytes. Reassembly is bounded to four 64 KiB
  messages, 128 completed-operation records, and fixed timers; only one file is
  open at a time. VPN sending is capped at 200 packets/second with bounded kernel
  queues. No compression or application multiplexing is implemented.
* Packet timing, endpoints, sizes, identifiers, and handshakes are visible. The
  remote kernel may echo ciphertext back; this adds traffic, not a second data
  delivery. No key logging, remote execution, or remote-specified destination paths.

Source references: [Noise](https://noiseprotocol.org/noise.html),
[cryptography AEAD](https://cryptography.io/en/latest/hazmat/primitives/aead/),
[HKDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/),
[Python sockets](https://docs.python.org/3/library/socket.html),
[Microsoft raw sockets](https://learn.microsoft.com/en-us/windows/win32/winsock/tcp-ip-raw-sockets-2),
and [Linux TUN](https://docs.kernel.org/networking/tuntap.html).

## Develop and verify

The [measurement guide](docs/measurement.md) covers ordinary ICMP/Pingo PCAP
comparisons, held-out detection and false-positive rates, bandwidth, echo RTT, and
optional offline distribution encoding, padding, and timing experiments. Install
`.[research]` and use `pingo-measure` with a capture manifest. These experiments do
not change the live transport; real captures are required to assess their value.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m compileall -q src
```

On Linux, use `.venv/bin/python`. Tests use connected in-memory carriers and a
mock TUN/route runner; no administrator privileges or live routing changes.
They cover cryptographic tampering/reordering/replay, handshake loss/restarts,
packet decoding, fragmented transfers under data/ACK loss and duplication,
streamed file integrity/quota/safe completion, VPN packets, and route rollback.

Code layout: `crypto.py` defines session protection, `icmp.py` the raw carrier,
`transport.py` the authenticated session/keepalive engine, `reliable.py` bounded
reliable blobs, `direct.py` application transfers, and `vpn.py` Linux TUN/routes.
Application modes do not implement their own encryption or ICMP framing.

The [wire protocol](docs/protocol.md) describes packet formats and session behavior.
[Security](SECURITY.md) covers key management and protocol boundaries. The
[testing guide](docs/testing.md) documents test commands and isolated networking
tests. CI runs unit tests on Windows/Linux and Linux networking tests inside
disposable container namespaces.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
