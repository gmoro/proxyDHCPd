## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Insecure Umask in Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` used `os.umask(0)`, which creates files with world-writable permissions (0o666 or 0o777) by default. This could allow an attacker to modify sensitive files (like log files) created by the daemon.
**Learning:** This existed because `os.umask(0)` is sometimes mistakenly thought to 'reset' permissions safely, when in reality it removes all default restrictions, maximizing the permissions of newly created files.
**Prevention:** Always use a secure umask, such as `0o022`, when daemonizing processes to ensure files are not created world-writable.
