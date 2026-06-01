## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2025-06-01 - [Medium] Strict IP address validation
**Vulnerability:** IP address validation using `re.match(r"\b...\b")` incorrectly allowed trailing characters like newlines due to how `re.match` anchors at the beginning and the behavior of the `\b` boundary.
**Learning:** In Python, `re.match` checks for a match only at the beginning of the string. The `\b` anchor only ensures a word boundary, meaning a newline following the IP acts as a boundary and trailing invalid data is ignored by the matching engine.
**Prevention:** Always use `re.fullmatch` for strict string validation to guarantee the entire input conforms to the pattern.
