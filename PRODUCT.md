# Pingo

Pingo is a native desktop app for encrypted peer-to-peer messages, files, and IPv4 VPN
traffic over ICMP. Users configure a second computer using a shared key, start Receive
there, then send locally. Both computers need appropriate permissions and reachable IPv4s.

The primary job is sending and receiving. VPN and diagnostics are secondary workflows.
Users need every assigned local IPv4, labeled by adapter, to configure real peers.
Local checks cannot prove remote reachability. Peer verification is explicit.

Keep messages, files, resumable transfer progress, VPN controls, recovery, and detailed
packet traces accessible. Protect keys and render incoming text safely. Windows, macOS,
and Linux are supported. The UI is local HTML inside pywebview.

The user requests substantial simplification and a polished modern interface that
follows the system light/dark preference. Existing clutter is not a visual constraint.
