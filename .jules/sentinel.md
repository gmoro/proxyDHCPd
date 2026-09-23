## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-09-23 - DoS via TypeError in Python 3 Array Indexing
**Vulnerability:** Python 3 migration caused legacy division (/) to return a float instead of an int. When used as an array index during network packet MAC address parsing, it raised a TypeError, crashing the daemon.
**Learning:** Mathematical operations on bytes from network packets that are used as list indices or sizes must be strictly typed as integers to avoid DoS on Python 3.
**Prevention:** Always use floor division (//) or int() casting for array indices, or use pythonic formatting (e.g. "%02x") when processing raw bytes.
