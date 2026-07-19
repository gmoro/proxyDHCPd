## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Umask (CWE-732) during Daemonization
**Vulnerability:** In `proxydhcpd/cli.py`, the daemonization process explicitly set `os.umask(0)`. This caused any files or logs subsequently created by the daemon to be world-writable (permissions like 666 or 777), allowing any unprivileged user on the system to tamper with them.
**Learning:** This likely existed because `os.umask(0)` is sometimes blindly copied from basic daemonization tutorials which intend to clear the parent's umask, but fail to establish a secure restrictive umask for the child.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` or `os.umask(0o027)` when daemonizing processes to ensure that newly created files enforce strict permissions by default.
