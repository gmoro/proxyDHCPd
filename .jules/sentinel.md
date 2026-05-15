## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Privilege Escalation via Insecure Umask
**Vulnerability:** The daemon process in `proxydhcpd/cli.py` used `os.umask(0)` during double-fork daemonization. This removes all permission restrictions on subsequently created files (such as log files or PID files), defaulting them to world-writable (e.g., 666 for files, 777 for directories), allowing any user on the system to tamper with them.
**Learning:** Insecure umasking is a common pitfall in Python daemonization scripts that copy boilerplate without adjusting for security.
**Prevention:** Always use a secure umask like `0o022` to ensure group and other users do not have write access to daemon-created files.
