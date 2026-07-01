## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Daemon Umask
**Vulnerability:** The daemonization routine in `proxydhcpd/cli.py` called `os.umask(0)`, causing any files created subsequently by the daemon process (e.g., logs or configuration dumps) to be world-writable by default (permissions 777 or 666 depending on `open()` arguments).
**Learning:** `os.umask(0)` is an anti-pattern when daemonizing, often copied blindly from old C examples without understanding that it zeroes out the process's file mode creation mask, effectively dropping all permission protections.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` during daemonization to enforce standard protections, ensuring new files are readable but not writable by other users.
