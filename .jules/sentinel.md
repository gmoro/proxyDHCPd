## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Unhandled Exceptions in Packet Logging
**Vulnerability:** Generating string representations of raw network packets (e.g., in `DhcpPacket.str()`) could throw unhandled exceptions (like `IndexError` or `TypeError`) on malformed or truncated payloads, crashing the daemon.
**Learning:** This existed because logging functions inherently trust the structural integrity of the network packet and didn't employ defensive error handling.
**Prevention:** Wrap operations that generate string representations or log raw network packets in a generic `try...except` block to prevent unhandled exceptions from crashing the daemon.
