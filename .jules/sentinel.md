## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Silent Type-Mismatch Bypass in Network Protocol Field Validation
**Vulnerability:** In `pydhcplib`'s `SetOption` method, fixed-length DHCP fields were validated by directly comparing a list of constraints (`specs`) to an integer `length` (`specs==length`). Python silently evaluated this as `False`, which allowed invalid-length data to bypass the strict check and fall through to the less-strict variable-length check.
**Learning:** The root cause is a silent type-mismatch bypass in Python where comparing incompatible types evaluates to `False` without raising a TypeError.
**Prevention:** Always compare equivalent types. For list-based constraints, explicitly compare against the specific list index (e.g., `specs[0] == length`) rather than the entire list structure.
