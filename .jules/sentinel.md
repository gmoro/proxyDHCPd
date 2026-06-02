## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Umask During Daemonization
**Vulnerability:** The daemonization process in `proxydhcpd/cli.py` set the file creation mask to `0` using `os.umask(0)`. This caused newly created files by the daemon, such as logs, to be world-writable, allowing any user on the system to tamper with them.
**Learning:** This vulnerability existed due to incorrect boilerplate daemonization code being used where the umask is decoupled from the parent but not properly restricted for secure operations.
**Prevention:** Always use a secure file creation mask, such as `os.umask(0o022)`, when daemonizing processes to ensure that log files and other artifacts are not created with overly permissive permissions.
