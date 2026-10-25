## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-11-20 - Silent Type-Mismatch Bypass in Network Protocol Field Validation
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `SetOption` incorrectly compared the `specs` list directly to an integer `length` (`specs==length`). Python evaluates this as `False` without raising an error, which caused fixed-length fields to fall through and be validated against less strict, variable-length validation branches.
**Learning:** This existed because Python's dynamic typing allows comparing different types without raising exceptions, hiding logic flaws in data validation.
**Prevention:** Ensure type strictness when validating fixed-length network protocol fields and avoid comparing lists/tuples directly to integers.
