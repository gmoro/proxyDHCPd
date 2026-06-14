## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure Umask on Daemonization
**Vulnerability:** The proxy DHCP daemon incorrectly called `os.umask(0)` during its daemonization process in `proxydhcpd/cli.py`. This zeroed out the process file mode creation mask, meaning any subsequent files (such as logs or dynamic configuration) created by the daemon would be world-writable (`rw-rw-rw-` or `0666`), potentially allowing unprivileged users to modify proxy configuration or logs on the server.
**Learning:** This occurred due to a misunderstanding of how `os.umask()` works when daemonizing in Python. The value passed is what is masked out, not what is kept. A mask of 0 removes all restrictions.
**Prevention:** Always use a restrictive mask, such as `0o022`, when setting the umask during daemonization to ensure new files are not writeable by group or others.
