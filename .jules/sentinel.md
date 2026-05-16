## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Insecure Umask During Daemonization
**Vulnerability:** The daemon initialization code in `proxydhcpd/cli.py` called `os.umask(0)`, which meant any files or directories created by the daemon would be world-writable by default.
**Learning:** This existed because `os.umask(0)` is sometimes misunderstood as a way to reset the umask, but it actually removes all restrictions, leading to permissive default file permissions.
**Prevention:** Always use a secure umask like `0o022` or `0o027` when explicitly setting the umask during daemonization to ensure sensitive files like logs aren't accidentally exposed.
