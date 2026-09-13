## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-09-13 - DoS via TypeError in MAC Address Parsing
**Vulnerability:** Legacy Python 2 division (`/`) was used in array indexing in MAC address parsing, returning a float in Python 3 and causing a `TypeError`. This could crash the DHCP daemon when parsing malformed or specific packets.
**Learning:** Always consider Python 3 behavior with legacy division when porting legacy Python 2 codebase, especially in array indices.
**Prevention:** Use floor division (`//`) or replace custom array math parsing logic with robust, native formatters like `%` string formatting.
