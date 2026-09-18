## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - DoS via TypeError on Python 3 Legacy Division
**Vulnerability:** In `pydhcplib`'s `dhcp_packet.py`, MAC address formatting used legacy division `data[iterator]/16` as a list index. In Python 3, this returns a float, raising a `TypeError` that crashes the daemon when processing or logging packets. Additionally, assuming a fixed length of 6 without bounds checking could lead to an `IndexError` on malformed packets.
**Learning:** This existed due to a direct migration from Python 2 without testing string representations of packets containing MAC address fields. The assumption of well-formed, fixed-length fields also persists.
**Prevention:** Avoid legacy division for integer math in Python 3 (use `//` or `int()`), and prefer standard formatting like `"%02x"` which is cross-compatible and safer. Always bounds-check or slice safely (e.g. `data[:6]`) when handling network buffers.
