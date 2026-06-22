## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Default File Permissions via Daemon Umask
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` called `os.umask(0)`, which clears the default file creation mask. Consequently, any files or logs subsequently created by the daemon would be world-writable (e.g., permissions 0666).
**Learning:** This existed due to older daemonization templates or tutorials often suggesting `os.umask(0)` to reset permissions without considering the security implications for file and log generation.
**Prevention:** Always use a secure umask like `os.umask(0o022)` when detaching processes to ensure newly created files drop group and other write permissions by default.
