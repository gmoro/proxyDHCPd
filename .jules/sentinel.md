## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-03 - World-Writable Files due to Insecure Umask During Daemonization
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` called `os.umask(0)` to decouple from the parent environment, which resulted in a file creation mask of 0. This caused newly created files, such as the proxy log file, to be world-writable by default, potentially allowing unprivileged users on the system to tamper with logs or escalate privileges.
**Learning:** This existed because `os.umask(0)` is commonly (but incorrectly) cited in older Python daemonization tutorials to clear any inherited restrictive mask. However, it completely drops all default file permission protections.
**Prevention:** Always use a secure file creation mask like `os.umask(0o022)` when daemonizing processes to ensure that newly created files retain secure default permissions (e.g., owner-write only, group/others read-only or no access).
