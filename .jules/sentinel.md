## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Insecure File Creation Mask During Daemonization
**Vulnerability:** The daemon initialization logic in `proxydhcpd/cli.py` called `os.umask(0)`, which sets the file creation mask to 000. This causes any files created subsequently by the daemon process (e.g., logs, temporary files) to be created world-writable, allowing unprivileged users to modify them.
**Learning:** Calling `os.umask(0)` is a common anti-pattern often copy-pasted from older daemonization scripts, but it creates a dangerous environment where all created files lack restrictive permissions.
**Prevention:** Always use a restrictive mask such as `os.umask(0o022)` (rw-r--r--) or `os.umask(0o077)` (rw-------) when dropping parent privileges in a daemon process to ensure newly created files remain secure by default.
