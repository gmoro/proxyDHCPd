## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Information Exposure via Stack Traces and Insecure Umask
**Vulnerability:** The daemon initialization logic in `proxydhcpd/cli.py` and the main packet loop in `proxydhcpd/dhcpd.py` caught generic exceptions and printed them using `traceback.print_exc()`, which leaks internal application details to standard output/logs. Additionally, `os.umask(0)` was used during daemonization, creating files with overly permissive (world-writable) permissions.
**Learning:** These existed due to copy-pasting standard daemonization boilerplate without considering the security implications of umask defaults and generic exception handling.
**Prevention:** Always use a secure umask (e.g., `0o022`) when daemonizing to ensure files default to `644`/`755`. Replace `traceback.print_exc()` with `logger.error()` in production code to avoid exposing stack traces.
