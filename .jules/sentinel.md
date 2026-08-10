## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS TypeError in Packet Stringification
**Vulnerability:** A `TypeError` occurs when attempting to cast float division results to integers while generating human-readable MAC addresses in `DhcpPacket.str()` on Python 3 environments.
**Learning:** This bug demonstrates the risk of migrating code originally designed for Python 2 (where `/` on integers yielded an integer) to Python 3 without accounting for `/` yielding a float. Furthermore, placing raw payload extraction routines in unguarded logging contexts can turn simple parse failures into critical daemon crashes (DoS).
**Prevention:** Avoid legacy format handling for binary types, instead utilizing `"%02x"` format strings or `.hex()`. Additionally, always wrap complex packet logging/stringification methods in a generic `try...except` block, ensuring that malformed or truncated network payloads only result in a degraded log message rather than an unhandled exception crashing the server.
