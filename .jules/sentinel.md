## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-03-30 - Insecure Default File Permissions During Daemonization
**Vulnerability:** In `proxydhcpd/cli.py`, the daemonization process called `os.umask(0)`, meaning any files created by the daemon (e.g., log files) would be world-writable by default (`rw-rw-rw-`).
**Learning:** This existed because standard double-fork daemonization templates often include `os.umask(0)` to ensure the daemon can write files without inheriting restrictive umasks from the shell. However, leaving it at `0` without manually restricting permissions on subsequent file creations exposes the system.
**Prevention:** Always use a secure umask (like `0o022`) during daemonization to ensure default file permissions are restricted, allowing read and write only by the owner, and read-only for others.
