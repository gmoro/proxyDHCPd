## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-10-09 - DoS via Unhandled Exceptions in Packet Stringification
**Vulnerability:** The `str()` method in `DhcpPacket` crashed when processing malformed packets or standard packets in Python 3 due to legacy division `data[iterator]/16` returning a float instead of an integer. This caused an unhandled `TypeError` (or `IndexError` on truncated packets) which could crash the daemon when logging or inspecting network traffic.
**Learning:** This existed because legacy Python 2 code paths were not fully audited for Python 3 compatibility, and logging/stringification methods lacked defensive exception handling against malformed network data.
**Prevention:** Always wrap non-critical operations like packet stringification in `try...except` blocks to prevent unhandled exceptions from crashing the main daemon loop, and sanitize list slicing/formatting when porting code to Python 3.
