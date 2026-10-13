## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Bypass of fixed-length validation due to silent type mismatch
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `SetOption` had a length validation bypass (`specs==length` where `specs` is a list and `length` is an int). This allowed invalid data lengths for fixed-length fields, leading to malformed packet generation or parsing errors.
**Learning:** Python silently evaluates list vs integer comparison to False without throwing an error, leading to logic fall-through into variable-length validation branches.
**Prevention:** Always compare integers with integers, and strictly enforce variable-length logic only when the fixed-length specification indicates it is a variable-length field (e.g. `specs[0] == 0`).
