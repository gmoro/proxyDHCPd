## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-21 - Insecure File Permissions in Daemonization (CWE-732)
**Vulnerability:** The daemon initialization code in `proxydhcpd/cli.py` called `os.umask(0)`, which meant any files or logs subsequently created by the daemon process would be world-writable (permissions like 0666).
**Learning:** Setting the umask to 0 is a common anti-pattern when daemonizing processes, meant to give the daemon full control over its file permissions. However, it requires the daemon code to explicitly set secure permissions on every created file, which is error-prone.
**Prevention:** Always use a secure default umask, such as `os.umask(0o022)`, when writing daemon initialization logic to ensure files are created with safe default permissions (like 0644 or 0755).
