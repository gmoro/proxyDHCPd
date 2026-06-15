## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-15 - Prevent World-Writable Files during Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` explicitly reset the umask to `0` (`os.umask(0)`), causing any subsequently created files or logs (by the process or subprocesses) to be created world-writable.
**Learning:** During the classic double-fork daemonization pattern, it's common practice to decouple from the parent process by resetting the umask. However, resetting it to `0` removes all file permission constraints. This issue existed because of blindly following historical daemonization boilerplates.
**Prevention:** Always reset the umask to a restrictive value (e.g., `os.umask(0o022)`) during daemonization to ensure newly created files aren't unnecessarily exposed to unauthorized modifications.
