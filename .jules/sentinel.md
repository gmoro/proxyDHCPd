## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-05-19 - Insecure Daemon Umask
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` used an insecure umask of 0 (`os.umask(0)`), causing newly created files/logs by the daemon to be world-writable by default.
**Learning:** This is a common oversight when following standard double-fork daemonization boilerplate where the process fully detaches from its parent environment.
**Prevention:** Always use a secure umask like `0o022` when detaching from the parent environment to ensure system-created files maintain restricted permissions.
