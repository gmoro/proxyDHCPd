## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-28 - Insecure Default Umask During Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` explicitly set the file creation mask to `0` (`os.umask(0)`). This meant that any files created by the daemon (like logs, PID files, or temporary files) would be created with world-writable permissions (e.g., `rw-rw-rw-`), potentially allowing unprivileged users to modify them.
**Learning:** This is a common anti-pattern in daemonization scripts copied from older tutorials. While it clears inherited restrictions, it fails to establish secure default permissions for the background process.
**Prevention:** When decoupling a process from its parent environment, always explicitly set a restrictive umask (e.g., `os.umask(0o022)` or stricter) to ensure newly created files are secure by default.
