## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - DoS via TypeError in Packet String Representation
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DhcpPacket.str()` used legacy float division `/` to compute array indices when converting hardware MAC addresses. This causes a `TypeError: list indices must be integers or slices, not float` on Python 3, crashing the daemon if unhandled during logging or debug printing of malformed packets.
**Learning:** This existed because the codebase was partially migrated from Python 2 where `/` performed integer division, missing explicit casts.
**Prevention:** Always use floor division `//` or string formatting like `"%02x"` when calculating indices or formatting network bytes in cross-compatible code.
