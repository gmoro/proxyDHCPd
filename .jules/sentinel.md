## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-03-24 - DoS via IndexError in GetHardwareAddress
**Vulnerability:** The `GetHardwareAddress()` method in `proxydhcpd/dhcplib/dhcp_packet.py` retrieved the hardware length with `self.GetOption("hlen")[0]` without verifying if `hlen` existed. For malformed or too short packets, `self.GetOption("hlen")` returns an empty list, causing an `IndexError` which propagates and can crash the main DHCP daemon thread processing the packet, leading to a Denial of Service (DoS).
**Learning:** `pydhcplib`'s assumptions that all DHCP packets contain complete, well-formed base headers (specifically the first 240 bytes) are flawed and represent DoS vulnerabilities against the consuming service if not bounds checked.
**Prevention:** Always verify that array-returning parsing functions like `GetOption()` yield non-empty arrays before directly accessing their elements (e.g., `[0]`).
