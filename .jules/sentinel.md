## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Unhandled TypeError in Packet Stringification
**Vulnerability:** Calling `.str()` on `DhcpPacket` caused a `TypeError` due to Python 3 returning float for `/` division when rendering hardware MAC addresses, potentially crashing the proxy DHCP server if packets are logged or formatted.
**Learning:** Legacy Python 2 syntax hiding in untested string representation code can become DoS attack vectors in Python 3 network daemons.
**Prevention:** Use standard `//` integer division for hex manipulation across the board.
