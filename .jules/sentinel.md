## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-21 - World-Writable Files via Insecure Daemon Umask
**Vulnerability:** The proxy DHCP daemon (`proxydhcpd/cli.py`) called `os.umask(0)` during the daemonization fork sequence. This removed all file mode creation masks, meaning any configuration files, pid files, or logs subsequently created by the daemon would be world-writable (e.g., `rw-rw-rw-` permissions), leading to a CWE-276 vulnerability.
**Learning:** This vulnerability existed because the developer copy-pasted generic, outdated daemonization boilerplate code that incorrectly assumed the application would handle all explicit `chmod` calls later, prioritizing decoupling from the parent environment over secure defaults.
**Prevention:** Always use a restrictive umask such as `os.umask(0o022)` (or `0o027`) during daemonization to ensure newly created files default to secure permissions.
