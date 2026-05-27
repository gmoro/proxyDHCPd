## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS via Partial Regex Matching in IP Validation
**Vulnerability:** The configuration parser (`parse_config`) used `re.match` to validate IP addresses. `re.match` only enforces matching at the beginning of the string. This allowed trailing garbage characters (e.g., `192.168.1.1; bad_command`) to pass validation and be injected into internal configuration state.
**Learning:** This vulnerability existed because of a misunderstanding of the Python `re` module; `re.match` is not anchored to the end of the string, even with word boundaries (`\b`), if trailing characters are appended after the boundary.
**Prevention:** Always use `re.fullmatch` for strict input validation to ensure the entire input exactly conforms to the specified pattern.
