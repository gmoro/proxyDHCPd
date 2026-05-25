## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Insecure File Permissions via Daemon Umask
**Vulnerability:** The proxy daemon process explicitly called `os.umask(0)` when backgrounding, stripping the system's default umask and causing newly created files (e.g., logs, PID files) to be world-writable (permissions `666` or `777`).
**Learning:** This is a common pitfall in older daemonization boilerplate code that zeroes the umask to give the daemon a "clean slate" without realizing it creates insecure file permissions by default (CWE-732).
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes to ensure files are read/write by the owner, and only readable by group/others.
