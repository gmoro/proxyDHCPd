## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-10-24 - Bypass of Fixed-Length Validation in DHCP Options
**Vulnerability:** In `pydhcplib`'s `SetOption`, the length validation for fixed-length DHCP options incorrectly compared a list to an integer (`specs == length`), evaluating to `False`. This bypassed the strict fixed-length check and fell back to lax variable-length constraints, allowing malformed data (like a 5-byte IPv4 address) to be accepted.
**Learning:** Python's silent type-mismatch in equality comparisons causes logic to fall through to less strict branches without throwing an error, silently undermining logic boundaries in network parsing code.
**Prevention:** Always compare exact types and explicitly enforce mutually exclusive validation branches (e.g., verifying `specs[0] == 0` before allowing variable-length checks).
