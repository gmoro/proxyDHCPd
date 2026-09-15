## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-03 - DoS via TypeError in Logging Network Packets
**Vulnerability:** A `TypeError` occurs when stringifying `hwmac` options in `DhcpPacket.str()` due to Python 3 legacy division `data[iterator]/16` producing floats. This can crash the daemon when logging or printing raw/malformed packets.
**Learning:** Legacy Python 2 code that relies on integer division `/` will break in Python 3. Because lists don't accept float indices, this results in a predictable denial-of-service point on any code path that attempts to log or represent the option.
**Prevention:** Use string formatting like `"%02x" % each` instead of mathematical arithmetic for hex conversion, or explicitly cast division to `int()` or use `//`.
