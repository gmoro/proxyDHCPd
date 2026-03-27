## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-01 - [IndexError in GetHardwareAddress]
**Vulnerability:** The GetHardwareAddress method in dhcp_packet.py accesses index 0 of the result from GetOption("hlen") without checking if the list is empty. If the option is missing or malformed, this raises an IndexError, potentially causing a Denial of Service (DoS).
**Learning:** The embedded pydhcplib library parsing functions like self.GetOption() may return empty lists for truncated or malformed network payloads. Always verify the array is non-empty before accessing indices.
**Prevention:** Always verify that lists returned by parsing functions are non-empty before accessing specific indices.
