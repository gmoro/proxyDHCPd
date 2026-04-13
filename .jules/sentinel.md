## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-04-13 - DoS via IndexError on empty GetOption in DHCP Packet Parse
**Vulnerability:** A Denial of Service (DoS) vulnerability existed in `GetHardwareAddress()` where it attempted to access `self.GetOption("hlen")[0]` without verifying the list wasn't empty. Malformed packets with missing options returned an empty list, causing an `IndexError`.
**Learning:** Raw network parsing libraries (like `pydhcplib`) often fallback to returning empty lists `[]` instead of `None` or raising structured exceptions when fields are missing or corrupted.
**Prevention:** Always verify the length of lists returned by dynamic packet parsing functions before accessing indices (e.g., `if hlen_opt:` instead of `if hlen_opt != []`), especially in network services exposed to arbitrary client traffic.
