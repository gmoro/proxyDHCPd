## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-27 - Insecure umask during Daemonization
**Vulnerability:** The daemonization code in `proxydhcpd/cli.py` called `os.umask(0)`, which set the file creation mask to 0. This caused any files created subsequently by the daemon process (e.g. proxy.log, or files created by child processes) to be world-writable (permissions like `rw-rw-rw-`).
**Learning:** This is a common but dangerous pattern where daemonization logic attempts to 'clear' inherited umasks without setting a restrictive default, inadvertently maximizing file permissions for newly created files.
**Prevention:** Always use a restrictive umask such as `os.umask(0o022)` during daemonization unless there is a specific, explicitly documented reason not to. This ensures files default to secure permissions (e.g., `-rw-r--r--`).
