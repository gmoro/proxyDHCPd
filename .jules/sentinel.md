## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-10-18 - Insecure File Permissions via os.umask(0)
**Vulnerability:** The daemonizing process in `proxydhcpd/cli.py` used `os.umask(0)`, which creates files (like logs and PID files) with world-writable permissions (e.g., `rw-rw-rw-`).
**Learning:** This is a common mistake when detaching processes (double-forking) from a parent, as typical POSIX daemonizing tutorials might demonstrate `umask(0)` to completely decouple from parent settings. However, doing so without setting explicit file permissions afterwards introduces a local privilege escalation or tampering risk.
**Prevention:** Use a secure default mask such as `os.umask(0o022)` when detaching, which ensures newly created files have safe permissions (e.g., `rw-r--r--`).
