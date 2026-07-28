## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Input Validation Bypass via Partial Regex Matching
**Vulnerability:** The `ipAddressCheck` method in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string, allowing strings with a valid IP followed by trailing garbage characters (e.g., `"192.168.1.1 and some injection payload"`) to pass validation. This is a CWE-185 vulnerability.
**Learning:** This existed because `re.match` is commonly misunderstood as matching the entire string, whereas it only matches from the start.
**Prevention:** Always use `re.fullmatch` when performing strict regex-based input validation to ensure the entire input string conforms to the expected pattern, preventing partial matches and trailing garbage injection.
