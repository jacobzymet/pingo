# macOS

Pingo uses macOS's built-in libpcap for receiving ICMP echo requests and utun for
IPv4 VPN packets. It does not install a kernel extension or require Wintun.
The desktop uses pywebview's Cocoa/WebKit backend. Networking requires root;
ordinary unprivileged startup can still create and edit connections.

## Start from source

Use a current Python 3.11+ installation. Create a fresh environment when changing
Python versions:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[gui]'
sh 'Start Pingo.command'
```

The launcher asks for administrator privileges through `sudo`. Do not enter a
password into a Pingo form. You can also start directly:

```sh
sudo .venv/bin/python -m pingo gui
```

Connections and generated keys are stored under the original sudo user's
`~/Library/Application Support/Pingo`. App-owned keys, settings and received files
retain that user's ownership. A direct root login uses root's home instead.

Apple Silicon can install native dependency wheels. For Intel Macs, cryptography
50 builds from source; install Xcode Command Line Tools and the build dependencies:

```sh
brew install rust openssl@3 pkgconf
export OPENSSL_DIR="$(brew --prefix openssl@3)"
.venv/bin/python -m pip install -e '.[gui]'
```

## Messages and files

Create or import a connection, then use Receive on one computer and Message/File
on the other. Windows, Linux and macOS peers use the same version 0.3 wire protocol
and matching 32-byte shared key. Allow inbound IPv4 ICMP echo requests from the
other peer. A normal ping response does not prove that Pingo can receive requests.

Darwin's ICMP implementation consumes echo requests while replying to them, so
Pingo receives the original requests through a narrowly filtered libpcap capture
on the outer peer's interface. Captured Ethernet/loopback headers are removed
before the shared IPv4/ICMP/authentication checks. The normal raw socket sends
requests; kernel echo replies do not count as authenticated application delivery.

## VPN

The interface setting `pingo0` or `auto` allocates a fresh kernel-assigned `utunN`.
An explicit `utunN` requests that unused unit and never attaches to an existing
adapter. Routes and DNS use the actual kernel-assigned name.

Example client and responder (use complementary outer-peer configurations):

```sh
# Responder
sudo .venv/bin/python -m pingo vpn --config peer-b.toml \
  --listen --interface auto --address 10.77.0.2/30

# Client: tunnel subnet only, without system DNS changes
sudo .venv/bin/python -m pingo vpn --config peer-a.toml \
  --interface auto --address 10.77.0.1/30 --no-dns
```

Selected routes use `--route NETWORK`; default IPv4 routing uses `--default-route`.
The outer peer is pinned to its original physical route before tunnel routes are
added. Exit routing still requires forwarding/NAT configured separately on the
exit peer. IPv6 transport and IPv6 tunneling are unsupported.

### Kill switch and DNS

Default routing enables both unless explicitly overridden. The PF kill switch:

- Requires the standard loaded `com.apple/*` filter hook; refuses custom root
  rules, earlier anchors, skipped physical interfaces and retained Pingo protection.
- Adds an owned early anchor with loopback, IPv4 utun and peer-ICMP exceptions;
  blocks other IPv4/IPv6 traffic in both directions.
- Resets existing PF connection states when enabled, so existing connections may
  disconnect. It does not replace the root ruleset or edit `/etc/pf.conf`.
- Retains protection after a VPN failure; normal stop removes only its anchor
  and releases only its own PF enable reference.

Use `sudo /sbin/pfctl -sr` to inspect the active hook. Arrange a compatible PF
configuration with the machine's administrator if setup is refused. Pingo does
not replace another firewall's policy automatically. Explicitly disabling the
kill switch leaves outside traffic, including IPv6, subject to the host's policy.

Automatic DNS snapshots enabled network services, applies the chosen tunnel
resolvers, and restores the previous server lists on stop. Recovery records live
in root-owned `/Library/Application Support/Pingo/Recovery`.
If a service's DNS changes externally, cleanup leaves that change intact.
New automatic DNS setup refuses unresolved recovery records.

After a failure, stop any active Pingo instance and use Settings' recovery action
or run:

```sh
sudo .venv/bin/python -m pingo unlock
```

This restores owned DNS changes and removes recorded Pingo PF protection. utun
disappears when its control socket closes. Hard termination can leave an outer
peer host route requiring manual cleanup; ordinary stop reverses owned routes.
Do not change the underlying network while a VPN is active; stop and reconnect.

## Build and test

Build on each target architecture with a patched 64-bit Python environment:

```sh
sh scripts/build-macos.sh .venv/bin/python
```

The output is `dist/Pingo-macOS-arm64.zip` or `dist/Pingo-macOS-x86_64.zip`.
Unzip the whole folder. `Start Pingo.command` launches the app with networking
privileges; opening `Pingo.app` alone opens unprivileged configuration mode.
The worker remains inside the app. Builds are ad-hoc signed and are not notarized;
use Apple's normal signing/notarization process for distribution to other users.

CI includes Apple Silicon/Intel native app builds, a packaged Cocoa smoke test,
and opt-in kernel checks for request capture, utun lifetime and PF syntax. These
kernel checks do not change host routes, DNS or PF rules:

```sh
sudo env PINGO_MAC_LIVE=1 .venv/bin/python -m pytest -q -m live tests/live/test_macos.py
```

Exercise route/DNS/firewall behavior and crash recovery on an isolated Mac/VM
with a second peer before using default routing on a working machine.

References: [Apple utun API](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/if_utun.h),
[Apple ICMP implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/ip_icmp.c),
[libpcap API](https://www.tcpdump.org/manpages/pcap.3pcap.html),
[Apple networksetup documentation](https://support.apple.com/guide/remote-desktop/apdd0c5a2d5/mac),
[pywebview installation](https://pywebview.flowrl.com/guide/installation).
