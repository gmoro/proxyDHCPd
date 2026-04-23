## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-04-23 - Prevent Partial Matching in IP Validation
**Vulnerability:** The `ipAddressCheck` function used `re.match` to validate IP addresses. `re.match` only checks if the pattern matches at the beginning of the string, meaning an input like "192.168.1.1.bad" would return True. This could lead to a CWE-185 (Incorrect Regular Expression) partial match vulnerability where trailing garbage characters are accepted, potentially causing injection issues or logic errors.
**Learning:** Python's `re.match` behaves differently than strict validators; it acts as a "starts with" regex check. Security validation requires full string matches.
**Prevention:** Always use `re.fullmatch` for strict string validation instead of `re.match` to ensure the entire input exactly conforms to the expected pattern, preventing trailing data from slipping through.
