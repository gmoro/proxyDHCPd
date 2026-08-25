## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via TypeError/IndexError in packet formatting (Python 3 Migration)
**Vulnerability:** Calling `.str()` on a DHCP packet containing a truncated MAC address or when running in Python 3 caused a `TypeError` (because legacy `/` division returns a float which cannot index a list) or an `IndexError` (from iterating exactly 6 times even if the parsed option payload `data` was truncated by a malicious packet). This caused a crash when attempting to print or log packets.
**Learning:** This existed because the codebase was migrated to Python 3 where the behavior of `/` changed, and string formatting logic assumed network payloads were not truncated.
**Prevention:** Use type-safe string formatting instead of indexing math for hex encoding (e.g. `"%02x" % each`), and use list slicing `[:6]` which handles truncated lists gracefully without throwing an IndexError.
