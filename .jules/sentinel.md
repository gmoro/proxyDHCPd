## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Silent Validation Bypass via Type Mismatch
**Vulnerability:** In pydhcplib's option length validation (SetOption), the comparison specs == length evaluated a list against an integer. This silent type mismatch always returned False, causing fixed-length validations to fall through to a permissive branch, allowing arbitrary length payloads for fixed-length network options.
**Learning:** This existed because Python does not raise a TypeError when comparing different types for equality, and the original developer missed the [0] index on specs.
**Prevention:** Explicitly verify types in comparison operations and write unit tests asserting failure on invalid payload lengths.
