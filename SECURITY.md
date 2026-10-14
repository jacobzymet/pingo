# Security

Pingo uses a random 32-byte shared key and a Noise NNpsk0 handshake with fresh
X25519 ephemeral keys. Directional datagram keys derived with HKDF-SHA256 protect
traffic using ChaCha20-Poly1305 with full authentication tags.
Packet counters and an authenticated replay window reject duplicate and stale packets.

## Security boundaries

- The shared key identifies the peer. Use a different key for each peer pair and
  protect the key file on both computers.
- Version 0.3 provides forward secrecy for completed application sessions: later
  disclosure of the shared key alone does not decrypt recorded traffic when ephemeral
  and session secrets remain unavailable. Disclosure still permits future impersonation.
  Endpoint compromise, retained memory secrets, and earlier version 0.2 traffic are
  outside this guarantee. Python does not guarantee forensic memory erasure.
- Network observers can see endpoint addresses, packet sizes, timing, handshake
  markers, and ICMP identifiers. Pingo does not hide its use of ICMP.
- Received files, partial transfers, checkpoints, and keys are not encrypted at rest.
  Keep their directories private.
- A peer holding the shared key is trusted within the configured VPN source allowlist.
  Local administrators, the runtime, and the selected Wintun driver are also trusted.
- The Windows kill switch protects locally originated traffic, not router forwarding.
  Other firewall rules, DNS policies, and local proxies can affect connectivity.
- The macOS kill switch requires the standard PF anchor hook and resets existing
  PF connection states when enabled. It refuses conflicting or skipped PF policies.
  macOS automatic DNS changes use root-owned recovery records; stop or `pingo unlock`
  restores settings that still match Pingo's changes. Run only one active Pingo instance.

## Recovery

A VPN failure can leave Pingo's kill switch active. Stop the VPN and use
`pingo unlock` to remove Pingo's retained protection. On Linux, supply the exact
`--table` identity printed when the kill switch started. On Windows, unlock also
removes retained Pingo DNS policies. Hard termination can leave adapter or route
state requiring manual cleanup.

## Reporting vulnerabilities

Report vulnerabilities privately to the repository maintainer. Do not include
shared keys, private configurations, transferred files, or sensitive packet traces
in public issues.
