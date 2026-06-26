## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-23 - Insecure umask during daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` used `os.umask(0)`, meaning any files created by the background daemon (like log files, pid files) would be world-writable (permissions `666` or `777`).
**Learning:** Calling `os.umask(0)` is a common anti-pattern when daemonizing processes in Python, originally popularized by outdated Unix daemon examples. This creates a severe local privilege escalation risk if the daemon runs as root but creates files that unprivileged users can modify.
**Prevention:** Always use a restrictive umask such as `os.umask(0o022)` (or `0o027` for more restriction) when detaching from the parent environment to ensure safe default file permissions.
