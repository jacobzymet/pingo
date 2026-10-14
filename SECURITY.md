# Security

Pingo uses a random 32-byte shared key, an authenticated handshake, directional
session keys derived with HKDF-SHA256, and ChaCha20-Poly1305 authenticated encryption.
Packet counters and an authenticated replay window reject duplicate and stale packets.

## Security boundaries

- The shared key identifies the peer. Use a different key for each peer pair and
  protect the key file on both computers.
- The protocol does not provide forward secrecy. Compromise of the shared key
  permits impersonation and decryption of previously recorded sessions.
- Network observers can see endpoint addresses, packet sizes, timing, handshake
  markers, and ICMP identifiers. Pingo does not hide its use of ICMP.
- Received files, partial transfers, checkpoints, and keys are not encrypted at rest.
  Keep their directories private.
- A peer holding the shared key is trusted within the configured VPN source allowlist.
  Local administrators, the runtime, and the selected Wintun driver are also trusted.
- The Windows kill switch protects locally originated traffic, not router forwarding.
  Other firewall rules, DNS policies, and local proxies can affect connectivity.

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
