## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - DoS via Truncated Option Payloads in Packet Parsing
**Vulnerability:** In DecodePacket, the parser extracted DHCP option payloads using Python list slicing without validating that the end index was within the packet boundaries. Because Python list slicing silently ignores out-of-bounds indices, a truncated packet would result in a shorter-than-expected option value, causing downstream methods to crash with IndexError or TypeError.
**Learning:** Python's forgiving list slicing behavior can mask out-of-bounds memory reads, converting them into silent data truncation vulnerabilities that cause delayed crashes elsewhere in the application architecture.
**Prevention:** Always explicitly validate that the dynamically specified length of a network payload field fits within the remaining buffer before using list slicing for extraction.
