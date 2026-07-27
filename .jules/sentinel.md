## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Unhandled Exception in Packet Stringification
**Vulnerability:** The `DhcpPacket.str()` method lacked a generic `try...except` block. A malformed network payload bypassing earlier checks or an invalid length assignment could trigger `IndexError` or `TypeError` (such as legacy division `/` on lists in Python 3), crashing the entire ProxyDHCP daemon.
**Learning:** Legacy debug or stringification functions often assume well-formed internal state. If these functions are called during normal request logging, an unhandled exception becomes a remote DoS vulnerability.
**Prevention:** Wrap operations logging or generating string representations of raw network packets in generic `try...except` blocks to prevent unhandled exceptions from crashing the application.
