## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Bypass of fixed-length DHCP options validation
**Vulnerability:** In `pydhcplib`'s `SetOption`, fixed-length options were not strictly enforced because a list `specs` was compared to an integer `length`. Since this evaluated to false, it silently fell through to variable-length validation without error.
**Learning:** Silent type-mismatch bypasses can occur in Python when comparing collections to integers directly.
**Prevention:** Ensure correct element access when comparing lengths, and explicitly check `specs[0]==0` before applying variable-length validation.
