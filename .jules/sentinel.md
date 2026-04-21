## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-15 - Strict IP Validation
**Vulnerability:** `re.match` used for IP address validation, which allows malicious strings with a valid IP prefix (e.g. `192.168.1.1\n rm -rf /`) to pass validation. This could lead to downstream injection attacks if the IP is used in shell commands or logs without further sanitization.
**Learning:** `re.match` only checks for a match at the beginning of the string. `re.fullmatch` must be used to ensure the entire string matches the pattern.
**Prevention:** Always use `re.fullmatch` for strict input validation, or explicitly include `^` and `$` boundary anchors in the regex pattern.
