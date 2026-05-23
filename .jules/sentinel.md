## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Insecure Umask During Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` used `os.umask(0)`, meaning any newly created files and logs would be world-writable (with permissions up to `rw-rw-rw-`).
**Learning:** This is a common pitfall when developers follow older daemonization tutorials without adjusting for modern security defaults. Using `os.umask(0)` is insecure as it allows any user on the system to potentially modify proxy logs or configuration states if files are created post-daemonization.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` during process daemonization.
