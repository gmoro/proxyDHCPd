## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-18 - Insecure File Permissions During Daemonization
**Vulnerability:** The daemonized process was explicitly setting its umask to 0 (`os.umask(0)`), causing all subsequent files created by the daemon (like logs, sockets, or PID files) to be world-writable (e.g. 0666 or 0777).
**Learning:** Standard daemonization recipes sometimes include `os.umask(0)` to clear inherited umasks, but without resetting it to a secure value or using explicit permissions during file creation, it leaves the system vulnerable to local privilege escalation or tampering.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` during daemonization to ensure files are created with safe default permissions (e.g., 0644 or 0755).
