## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Partial Matching Vulnerability in IP Address Validation
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. Because `re.match` only checks for a match at the beginning of the string, it accepted invalid IP strings that started with a valid IP but contained trailing garbage characters (e.g., "192.168.1.1 garbage"). This could lead to configuration processing errors or potentially more severe injection issues down the line.
**Learning:** This vulnerability existed because the developer misunderstood the behavior of `re.match` in Python's `re` module, assuming it checked the entire string rather than just the beginning.
**Prevention:** When validating the entirety of a string against a regular expression pattern, always use `re.fullmatch` (or append `$` to the end of the pattern with `re.match`) to ensure strict validation without partial matches.
