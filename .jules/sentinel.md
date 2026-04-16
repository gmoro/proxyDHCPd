## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-04-16 - Partial Regular Expression Matches Leading to Input Validation Bypass (CWE-185)
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string, allowing inputs with valid prefixes followed by trailing garbage (e.g., `"192.168.1.1 garbage"`) to pass validation.
**Learning:** `re.match` is insufficient for strict input validation because it implicitly allows trailing characters. This could be exploited to inject malicious input or bypass security filters if the validated string is later used in system commands or other sensitive contexts.
**Prevention:** Always use `re.fullmatch` for exact string validation in Python, as it requires the regular expression to match the entire string from start to finish.
