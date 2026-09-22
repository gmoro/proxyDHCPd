## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-02-24 - DoS via Float Division TypeError in Python 3
**Vulnerability:** The legacy Python 2 codebase used standard division `/` to calculate hex values (`data[iterator]/16`) in `dhcp_packet.py`. In Python 3, this returns a float, causing a `TypeError` when used as an array index, which leads to a Denial of Service crash during packet formatting.
**Learning:** Security reviews must account for language migration side-effects. Code that was functionally safe in an older runtime version can introduce crashing vulnerabilities when ported to a newer runtime without strict type checking.
**Prevention:** Use floor division `//` or robust string formatting primitives (e.g., `"%02x" % var`) instead of manual division arrays to prevent runtime type crashes.
