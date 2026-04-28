## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-15 - Strict IP Address Validation

**Vulnerability:** IP address validation in `proxydhcpd/proxyconfig.py` was vulnerable to partial matches (CWE-185) due to the use of `re.match` which matched valid IP addresses followed by trailing garbage characters.

**Learning:** `re.match` only checks for a match at the beginning of the string, allowing strings like "192.168.1.1 garbage" to pass validation. This could potentially allow for bypass of IP address filtering or incorrect parsing.

**Prevention:** Always use `re.fullmatch` for exact string validation or append start/end anchors (`^` and `$`) to regular expressions intended to validate the entire input string.
