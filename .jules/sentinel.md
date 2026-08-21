## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Denial of Service via TypeError in Packet Logging
**Vulnerability:** The `DhcpPacket.str()` method used Python 2 legacy division (`data[iterator]/16`) when formatting MAC addresses for logging. In Python 3, this operation returned a float, which triggered a `TypeError: list indices must be integers or slices, not float` when used as an array index. This unhandled exception during packet logging could crash the DHCP daemon when handling a packet (Denial of Service).
**Learning:** Legacy codebase ported to Python 3 must be strictly audited for division operators. In network service logging paths, unhandled exceptions can turn simple debug/info logging into remote DoS vectors.
**Prevention:** Always use floor division `//` (or cast to `int()`) for array indices in Python 3. Furthermore, wrap logging/string formatting of raw binary network packets in generic `try...except` blocks to prevent parser errors from crashing the main daemon loop.
