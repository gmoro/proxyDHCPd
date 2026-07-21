## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Daemon umask resulting in world-writable files (CWE-732)
**Vulnerability:** The proxy DHCP daemon was setting `os.umask(0)` during double-fork daemonization. This completely disables the file mode creation mask, causing any subsequent files created by the background daemon (like log files, pidfiles, etc.) to be world-writable (e.g. 666 or 777 permissions).
**Learning:** This existed because of a legacy pattern where developers often blindly use `os.umask(0)` to clear inherited masks without explicitly resetting it to a safe value afterward, not realizing the security implications for file creation by the daemonized process.
**Prevention:** Always use a safe default umask like `os.umask(0o022)` during daemonization, ensuring that newly created files are writable only by the owner but still readable by the group/others (e.g. 644/755), rather than granting write access to all local users.
