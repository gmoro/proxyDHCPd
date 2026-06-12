## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Daemonization File Mask
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` used `os.umask(0)` to set the file mode creation mask. This could result in subsequently created files (like logs or configuration files) being world-writable, allowing unauthorized local users to modify them.
**Learning:** When a program sets its umask to 0 during daemonization, it inadvertently opens up permissions for any files created by the process, violating the principle of least privilege.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes. This ensures that new files are created with read and execute permissions for the group and others, but only write permissions for the owner.
