## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via TypeError in Legacy Division for MAC Address Formatting
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `str()` attempts to format hardware MAC addresses using legacy division (`data[iterator]/16`). In Python 3, this returns a float, causing a `TypeError: list indices must be integers or slices, not float`. A malformed packet triggering logging could crash the server daemon.
**Learning:** This existed because the codebase was likely ported from Python 2 without fully auditing integer vs float division semantics.
**Prevention:** Always use floor division `//` or cast to `int()` when calculating array indices, or better yet, use standard string formatting (like `"%02x"`) for byte-to-hex conversion which handles types correctly and avoids manual index calculations.
