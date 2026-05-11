## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2025-05-11 - [Input Validation] `re.match` is insufficient for strict IP address validation
**Vulnerability:** The configuration parsing logic used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string. This allowed trailing malicious payloads (e.g., `"192.168.1.1; rm -rf /"`) to bypass the check.
**Learning:** `re.match` is insecure for full-string validation, as it ignores trailing garbage characters (CWE-185).
**Prevention:** Always use `re.fullmatch` for strict input validation to ensure the entire string conforms to the expected pattern, preventing command injection or other malformed data attacks.
