## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Silent type-mismatch bypass in DHCP option validation
**Vulnerability:** In `pydhcplib`'s option setting logic, `SetOption` used `specs==length` instead of `specs[0]==length` for fixed-length DHCP options. Since `specs` is a list, Python evaluated `list == int` as `False` without raising an error. This caused fixed-length options (like IPv4 addresses) to fall through and be validated against variable-length constraints, allowing oversized, malformed network fields.
**Learning:** This existed because Python's dynamic typing silently returns `False` for type-mismatched equality comparisons, hiding the logical error.
**Prevention:** Ensure explicit type checking or correct list indexing (`specs[0]`) when comparing expected field properties to measured lengths in network protocol parsers.
