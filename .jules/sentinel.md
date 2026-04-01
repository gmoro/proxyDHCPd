## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Default File Permissions via `os.umask(0)`
**Vulnerability:** The proxy DHCP daemon set its umask to 0 (`os.umask(0)`) during the daemonization double-fork process. This causes any files created subsequently by the daemon (like log files, PID files, or caches) to be world-writable by default (e.g., `rw-rw-rw-`), potentially allowing unauthorized local users to tamper with the daemon's operation.
**Learning:** This pattern likely originated from standard Unix daemonization templates that carelessly clear the inherited umask without later restoring it to a secure default, failing to follow the principle of least privilege.
**Prevention:** Always set a secure umask (e.g., `0o022`) during daemonization to enforce safe default file permissions (e.g., `rw-r--r--`).
