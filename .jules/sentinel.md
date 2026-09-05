## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - DoS via TypeError in Packet String Representation
**Vulnerability:** In Python 3, legacy division (/) returns a float, which causes a TypeError when used as a list index in DhcpPacket.str() during hwmac formatting. This can crash the daemon on malicious or malformed packets.
**Learning:** This existed because the codebase was ported from Python 2 where division returned an integer.
**Prevention:** Always use // for integer division or "%02x" formatting for stringification of hex values.
