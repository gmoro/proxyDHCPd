## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2026-09-26 - Denial of Service via Unhandled Exception in Packet Logging
**Vulnerability:** The `DhcpPacket.str()` method crashed the daemon with a `TypeError` during MAC address formatting due to legacy Python 2 float division, and lacked exception handling for malformed packets.
**Learning:** Backend processes must not crash when stringifying user-supplied or network data, especially when logging.
**Prevention:** Wrap stringification and logging of raw network payloads in generic `try...except` blocks, and use backwards-compatible string formatting.
