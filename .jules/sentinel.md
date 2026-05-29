## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-05-29 - Secure Default umask
**Vulnerability:** Newly created files and logs were generated as world-writable due to `os.umask(0)` during daemonization.
**Learning:** This occurs when a daemon script fully clears its file creation mask without setting restrictive permissions later.
**Prevention:** Always use a secure umask such as `os.umask(0o022)` to enforce sane default permissions (`0o644` for files, `0o755` for directories).
