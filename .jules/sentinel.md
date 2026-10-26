## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Network Protocol Validation Bypass via Type Coercion
**Vulnerability:** In `pydhcplib`'s `SetOption`, the fixed-length verification `specs==length` compared a list (`specs`) directly to an integer (`length`). Python silently returns `False` for cross-type comparisons instead of raising a `TypeError`. This caused the strict fixed-length check to fail, allowing the logic to fall through to the less-strict variable length check, accepting invalid network payload lengths.
**Learning:** Python's silent evaluation of `list == int` as `False` can silently bypass security controls. In this case, `specs` was unexpectedly used instead of `specs[0]`.
**Prevention:** Explicitly assert expected types or decompose lists/tuples before comparison in security-critical validation paths. Avoid relying on inline boolean operators for complex validation fallbacks.
