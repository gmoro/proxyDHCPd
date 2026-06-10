## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Umask During Daemonization (CWE-732)
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` called `os.umask(0)`, which clears the file mode creation mask. This could cause newly created files and logs to be world-writable by default.
**Learning:** Legacy daemonization tutorials often advise `os.umask(0)` to reset inherited masks, but this introduces security risks in modern contexts where default restrictive masks are preferred to protect daemon-created artifacts.
**Prevention:** Always use a secure umask like `os.umask(0o022)` when explicitly decoupling from the parent environment to ensure safe default file permissions.
