## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-07-14 - Insecure umask during daemonization
**Vulnerability:** In `proxydhcpd/cli.py`, the daemonization process used `os.umask(0)`, which clears the file mode creation mask and causes newly created files and logs to be world-writable (CWE-732).
**Learning:** This likely occurred because standard double-fork daemonization boilerplate often clears the umask to ensure the daemon can write wherever it needs to, ignoring the security implication of broad permissions.
**Prevention:** Always use a safe umask such as `os.umask(0o022)` to ensure that files created by daemons or elevated processes remain protected against unintended modifications by other users on the system.
