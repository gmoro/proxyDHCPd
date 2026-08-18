## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - DoS via TypeError in str() on Malformed Packet
**Vulnerability:** Calling `packet.str()` on a maliciously crafted DHCP packet with an invalid MAC address representation causes a `TypeError: list indices must be integers or slices, not float`. This can lead to a Denial of Service.
**Learning:** Python 3 division (`/`) yields a float, which causes issues when used as an index into a list unless explicitly cast or done via floor division (`//`).
**Prevention:** Ensure proper types are used for array indexing and use floor division where integer results are required.
