## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Unhandled Exceptions in Packet String Generation
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DhcpPacket.str()` could throw an `IndexError` or `TypeError` (like float division on MAC address formatting) on malformed network payloads, crashing the ProxyDHCP daemon.
**Learning:** This existed because string generation logic implicitly trusted the packet contents to be well-formed and used legacy division `/` that fails in Python 3.
**Prevention:** Ensure logging and string representation methods for network payloads wrap operations in a generic `try...except` block or perform strict length validations.
