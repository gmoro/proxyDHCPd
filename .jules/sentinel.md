## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-03-01 - DoS via TypeError in hwmac packet parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DhcpPacket.str()` attempted to decode the `hwmac` address using legacy division `data[iterator]/16` to index into a hex symbol array. In Python 3, this returns a float, raising a `TypeError: list indices must be integers or slices, not float` which crashes the daemon.
**Learning:** This existed because of incomplete migration from Python 2 to Python 3. The original codebase assumed division of integers resulted in integers.
**Prevention:** Ensure format strings or integer floor division `//` are used for bitwise or array-indexing math when migrating Python 2 codebases to Python 3. Avoid rolling custom hex converters when standard string formatting (`"%02x"`) is safer and natively compatible.
