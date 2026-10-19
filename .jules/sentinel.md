## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-10-19 - Type Mismatch Bypass in DHCP Option Length Validation
**Vulnerability:** In `pydhcplib`'s `SetOption`, a fixed-length check compared a list (`specs`) directly to an integer (`length`). Python evaluates `[4, 0, 1] == 4` as False without raising an error. This caused the validation to fall through to the variable-length check (`specs[1] <= length`), allowing fixed-length fields (like IPv4 addresses) to accept arbitrary trailing bytes.
**Learning:** This existed because Python's dynamic typing allows silent failures when comparing mismatched types, whereas statically typed languages would catch this at compile time.
**Prevention:** Always verify that fixed-length network protocol fields are validated against the correct index of the specification tuple (e.g., `specs[0] == length`) and explicitly ensure mutually exclusive validation branches are used (e.g., checking `specs[0] == 0` for variable-length fields).
