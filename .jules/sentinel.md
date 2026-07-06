## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-07-06 - Insecure Umask on Daemonization
**Vulnerability:** The daemon process was setting `os.umask(0)` during double-fork initialization.
**Learning:** Setting umask to 0 makes all subsequently created files and logs world-writable by default, violating the principle of least privilege.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` when daemonizing to ensure newly created files are only writable by the owner.
