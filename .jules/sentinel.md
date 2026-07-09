## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-07-09 - Insecure umask during daemonization
**Vulnerability:** The daemonization logic in `proxydhcpd/cli.py` used `os.umask(0)`, which clears the process's file mode creation mask, causing newly created files (like logs) to be world-writable (CWE-732).
**Learning:** This existed because the standard recipe for double-forking sets umask to 0 so the daemon has full control over file creation permissions, but this application didn't later restrict file permissions when creating files.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` during daemonization unless there is a specific need for `0` (and files are created securely).
