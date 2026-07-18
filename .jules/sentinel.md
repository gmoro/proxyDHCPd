## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-10-24 - Insecure File Permissions During Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` used `os.umask(0)`, which clears the file mode creation mask and results in newly created files and logs being world-writable (0o666 or 0o777 permissions).
**Learning:** This occurred because clearing the umask with `os.umask(0)` is a common historical anti-pattern for "starting fresh" in a daemon environment, without realizing the severe security implications of world-writable files in modern systems.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes to prevent newly created files from being writable by other users.
