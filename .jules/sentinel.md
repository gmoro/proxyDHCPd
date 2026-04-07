## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-XX-XX - DoS via Unhandled IndexError in Packet String Representation
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `str()` and `GetHardwareAddress()` methods assumed that certain fields (like `op` code, `hlen`, or option arrays) always contained at least one element. If a packet was malformed or empty, accessing `data[0]` caused an `IndexError`, which could crash the daemon if `str()` or hardware address retrieval was called on unverified network data.
**Learning:** Empty arrays were returned by `GetOption()` and base data slices, and blindly assuming array elements exist in network parsing leads to unchecked exceptions.
**Prevention:** Always verify array length or existence (e.g., `if not data:` or `if hlen_opt:`) before accessing indices on parsed network payloads.
