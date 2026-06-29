## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-29 - Insecure umask in Daemon Process
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` used `os.umask(0)`, meaning any newly created files (e.g. logs, pidfiles) would be created with world-writable permissions if not explicitly prevented by the file creation function.
**Learning:** Using `os.umask(0)` is a common anti-pattern in daemonization tutorials, but it creates a significant local privilege escalation risk if a privileged daemon creates configuration or log files that other users can overwrite.
**Prevention:** Always use a restrictive umask like `os.umask(0o022)` (or stricter, like `0o027` or `0o077`) when daemonizing processes to ensure safe default permissions.
