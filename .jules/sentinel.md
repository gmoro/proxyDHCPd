## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - DoS via TypeError in Packet String Representation
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DhcpPacket.str()` used legacy Python 2 division (`/`) for `hwmac` address formatting. In Python 3, this returns a float, which causes a `TypeError` when used as an array index, crashing the ProxyDHCP daemon.
**Learning:** This existed because the codebase was migrated to Python 3 but retained legacy division formatting which behaves differently.
**Prevention:** Use strictly cross-compatible formatting methods like `":".join("%02x" % each for each in data[:6])` or integer division (`//`) when generating strings from binary payload arrays.
