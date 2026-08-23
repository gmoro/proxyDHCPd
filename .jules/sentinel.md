## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via TypeError in Packet Stringification
**Vulnerability:** In `pydhcplib`'s packet serialization (`dhcp_packet.py`), MAC address formatting used legacy division (`data[iterator]/16`) as an array index. In Python 3, this returns a float, leading to a `TypeError` crash whenever `DhcpPacket.str()` or logging functions attempt to stringify a payload with MAC addresses.
**Learning:** This vulnerability existed due to the migration from Python 2 to Python 3 where the behavior of the `/` division operator changed, and the fact that basic code paths like `__str__` were not fully tested under Python 3 execution environments.
**Prevention:** Avoid legacy division `/` for array indices in Python 3; either use integer division `//` or use built-in format specifiers (e.g. `"%02x"`) for byte-level stringification to remain cross-compatible.
