## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-10-12 - Silent Type-Mismatch Validation Bypass in DHCP Options
**Vulnerability:** In `pydhcplib`'s `SetOption` method, the fixed-length validation condition `specs == length` compared a list (e.g., `[4, 0, 1]`) to an integer length. Python silently evaluates this to `False` without raising an error. This caused the logic to fall through to the variable-length validation branch `length % specs[2] == 0`, effectively allowing DHCP options of any length (e.g., `ipv4` length 5) to bypass strict length enforcement.
**Learning:** This existed because Python's dynamic typing allows comparing different types without throwing an exception, leading to a silent failure of security-critical validation logic.
**Prevention:** Always ensure type consistency when validating fixed-length network protocol fields. Compare specific list/tuple indices (e.g., `specs[0] == length`) rather than comparing collections to integers directly.
