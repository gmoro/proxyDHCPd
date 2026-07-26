## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Input Validation Bypass via re.match
**Vulnerability:** The `ipAddressCheck` function in `proxyconfig.py` used `re.match` to validate IP addresses. `re.match` only validates that the beginning of a string matches the pattern, allowing an attacker to bypass validation by appending malicious payloads or garbage data to a valid IP address (e.g., `192.168.1.1; rm -rf /`).
**Learning:** This vulnerability pattern exists because it's a common misconception that `re.match` validates the entire string.
**Prevention:** Always use `re.fullmatch` for strict string validation when using regular expressions in Python to ensure the entire input conforms to the expected format.
