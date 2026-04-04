## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2025-04-04 - Insecure Umask During Daemonization
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` called `os.umask(0)`, causing any files or directories created by the proxy daemon to have world-writable permissions (e.g., 0666 or 0777) by default.
**Learning:** This is a common pitfall from old UNIX daemonization tutorials where setting umask to 0 is done to "gain full control," but in modern applications it easily leads to privilege escalation if file permissions are not explicitly managed upon creation.
**Prevention:** Always use a secure umask (e.g., `0o022` or `0o077`) when decoupling a process from its parent environment to enforce secure default file permissions.
