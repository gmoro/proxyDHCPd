## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-05-24 - Insecure umask during daemonization
**Vulnerability:** In `proxydhcpd/cli.py`, the daemonization process used `os.umask(0)`, which clears the file creation mask. This could result in newly created files (e.g., logs, PID files) being world-writable, exposing them to modification by unauthorized users (CWE-732).
**Learning:** This is a common but dangerous pattern in old daemonization snippets which attempt to clear the inherited umask without setting a secure replacement.
**Prevention:** Always use a secure umask like `os.umask(0o022)` when daemonizing, which ensures files are readable by others but only writable by the owner.
