## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-10-06 - DoS via Legacy Float Division in Packet Logging
**Vulnerability:** A Python 3 float division TypeError in dhcp_packet.py during hwmac formatting (data[iterator]/16) crashes the daemon when processing or logging malformed or specific packets.
**Learning:** Legacy Python 2 division syntax behaves differently in Python 3, returning floats. Using these floats as array indices creates an unhandled exception DoS vector.
**Prevention:** Avoid legacy division for array indexing or use cross-compatible formatting methods like `"%02x" % each`.
