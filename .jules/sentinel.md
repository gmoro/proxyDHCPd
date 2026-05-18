## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Default Umask during Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` explicitly set `os.umask(0)`, which meant any files subsequently created by the daemon would rely entirely on the permissions requested at creation time. If files (e.g., logs, PIDs) were created with default permissions (like 666), they would become world-writable, allowing unprivileged users to modify them.
**Learning:** This existed because `umask(0)` was likely used to "clear" the inherited umask to prevent the parent shell's umask from interfering with file creation, without realizing it removed all default permission restrictions.
**Prevention:** Always use a secure umask (e.g., `os.umask(0o022)`) during daemonization to enforce the principle of least privilege for default file permissions, ensuring group and other users cannot write to daemon-created files.
