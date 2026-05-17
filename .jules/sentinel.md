## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Insecure Default File Permissions via os.umask(0)
**Vulnerability:** In `proxydhcpd/cli.py`, the daemonization process was explicitly calling `os.umask(0)`. This unsets the file creation mask, causing any new files created by the daemon (like logs or PID files) to be world-writable (e.g., 0666) by default.
**Learning:** This is a common but dangerous copy-paste artifact from old daemonization guides that assumed processes would explicitly set secure permissions on every file they created.
**Prevention:** Always use a secure umask, such as `os.umask(0o022)`, during daemonization to enforce standard secure default permissions (owner writable, world readable) unless intentionally creating public files.
