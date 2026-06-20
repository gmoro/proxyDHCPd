## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-25 - Insecure Daemon umask configuration
**Vulnerability:** The daemon decoupled from its parent using `os.umask(0)`, causing any dynamically created system files or log handlers to potentially become world-writable.
**Learning:** Legacy system references sometimes advised overriding umask fully when calling daemon setup; modern security policies require preserving safe defaults via `0o022`.
**Prevention:** Avoid explicitly calling `os.umask(0)` in background Python services. Always employ a restrictive creation mask.
