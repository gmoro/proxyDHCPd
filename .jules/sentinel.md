## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-18 - Insecure File Permissions via os.umask(0)
**Vulnerability:** When daemonizing the `proxydhcpd` process in `cli.py`, the file mode creation mask was set to `os.umask(0)`. This caused any files subsequently created by the daemon (like proxy logs if the platform uses file logging, or PID files) to be world-writable by default (`rw-rw-rw-`).
**Learning:** This existed because `os.umask(0)` is sometimes used as a blanket way to decouple from the parent's environment, but it removes all default file creation protections.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes to ensure that only the owner has write permissions to newly created files.
