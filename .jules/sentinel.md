## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - DoS via Unhandled Exceptions in string representation
**Vulnerability:** The `DhcpPacket.str()` method throws unhandled errors (`TypeError`, `IndexError`) when attempting to parse and format malformed packets due to implicit length/type assumptions.
**Learning:** Legacy logging code that decodes arbitrary network bytes often lacks defensive error handling, leading to daemon crashes when attempting to stringify malformed packets.
**Prevention:** Always wrap raw packet formatting methods in `try...except` blocks and strictly validate data lengths before unpacking to prevent DoS via untrusted packet payloads.
