## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Default File Permissions via os.umask(0)
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, which sets the default file permissions mask to 0 for the daemon process. This means any files created by the daemon (like logs or configuration files) would be world-writable by default, allowing a malicious user to modify them and potentially compromise the system.
**Learning:** This existed because `os.umask(0)` is sometimes blindly copied from old daemonization guides that assumed the application itself would handle permissions, without realizing the security implications of world-writable defaults.
**Prevention:** Always use a secure umask, such as `os.umask(0o022)`, during daemonization to ensure default file permissions restrict write access to the owner while allowing read access for others.
