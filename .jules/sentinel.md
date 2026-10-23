## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Type-Mismatch in Network Validation
**Vulnerability:** The DHCP option validation logic failed to properly enforce fixed lengths due to a type-mismatch bug (`specs==length`). This evaluated to `False` silently, falling through to a less strict rule.
**Learning:** Python's dynamic typing allows comparing different types without raising an error. This can lead to logical flaws.
**Prevention:** Ensure correct indexing (e.g., `specs[0] == length`) when extracting constraint rules from data structures.
