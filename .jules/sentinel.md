## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Input Validation Bypass via Partial Regex Matching
**Vulnerability:** The `ipAddressCheck` method used `re.match` to validate IP addresses. `re.match` only checks if the pattern matches at the *beginning* of the string, which meant an IP address with trailing malicious input (e.g. `192.168.1.1; rm -rf /`) would still return `True`, bypassing the validation.
**Learning:** This is a common pitfall with Python's `re` module where developers expect `re.match` to validate the entire string.
**Prevention:** Always use `re.fullmatch` for strict validation to ensure the entire string matches the desired pattern.
