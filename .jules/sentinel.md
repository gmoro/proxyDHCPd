## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Float Division in MAC Address Parsing (Python 3)
**Vulnerability:** When parsing hardware MAC addresses (`hwmac`) to generate string representations in `DhcpPacket.str()`, the code used legacy division (`data[iterator]/16`). In Python 3, this returns a float, which causes a `TypeError` when used as an index for the `hexsym` list, potentially crashing the proxy daemon whenever it tries to log or display packets with MAC addresses.
**Learning:** This vulnerability existed due to incomplete migration from Python 2 to Python 3. The change in division semantics between versions created a hidden crash condition that only triggered during specific debug or logging paths.
**Prevention:** Always use floor division (`//`) or the integer constructor `int()` when calculating list indices in Python 3, or leverage modern string formatting (`"%02x" % var`) instead of manual hex array lookups.
