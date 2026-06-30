## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2025-02-28 - [CRITICAL] Insecure Daemon Umask
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` used `os.umask(0)`, which removes all default restrictions on file creation permissions, meaning files created by the daemon (like logs or pid files) would be world-writable by default.
**Learning:** Daemons decouple from their parent environment and often call `os.umask(0)` as part of a classic double-fork standard procedure just to "reset" the inherited umask. However, blindly setting it to `0` leaves it completely open.
**Prevention:** Always set a secure umask explicitly during daemonization, such as `os.umask(0o022)`, to ensure owner read/write and group/others read-only permissions on newly created files.
