## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Default Permissions via os.umask(0)
**Vulnerability:** In the daemonization logic within `proxydhcpd/cli.py`, the file creation mask was set to 0 (`os.umask(0)`). This meant that any files or logs subsequently created by the daemon would be world-writable (e.g., `rw-rw-rw-`), potentially allowing unauthorized local users to modify critical daemon logs or configuration files if created post-fork.
**Learning:** This likely occurred because of a copy-paste error from an outdated daemonization tutorial that cleared the inherited umask without setting a secure baseline.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` when decoupling a process from its parent environment, ensuring that newly created files have safe default permissions (e.g., `rw-r--r--`).
