## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure File Permissions via Zero umask
**Vulnerability:** The daemonization routine in `proxydhcpd/cli.py` called `os.umask(0)`, which sets the file creation mask such that newly created files (like logs or PID files) could potentially be world-writable (e.g., `chmod 666` or `chmod 777`).
**Learning:** This existed because it's a common, though insecure, boilerplate pattern copied from older daemonization guides that decoupled processes but failed to prioritize strict file permissions.
**Prevention:** Always use a restrictive umask such as `os.umask(0o022)` during daemonization to ensure sensitive files created by the service default to secure permissions (`644` or `755`).
