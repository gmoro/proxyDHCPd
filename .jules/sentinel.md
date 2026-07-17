## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Daemon File Creation Mask
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` sets `os.umask(0)`, causing any newly created files and logs to be world-writable.
**Learning:** Hardcoding a zero umask is a common oversight when daemonizing processes, meant to grant the daemon full control but inadvertently granting it to all users on the system.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` when dropping privileges or decoupling a process from the parent environment to maintain strict file permissions.
