## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Input Validation Bypass via Partial Regex Matching
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match()` to validate IP addresses. Because `re.match()` only checks if the string *starts* with the pattern, it allowed malformed or malicious strings (e.g., `192.168.1.1; rm -rf /`) to bypass validation, potentially leading to injection vulnerabilities if the validated IP was used downstream.
**Learning:** This occurred because developers often assume `re.match()` checks the entire string. In Python, `re.match()` matches at the beginning, `re.search()` matches anywhere, and `re.fullmatch()` requires the entire string to match the pattern.
**Prevention:** Always use `re.fullmatch()` (or explicitly anchor patterns with `^` and `$`) when validating input strings to ensure the entire string strictly conforms to the expected format and prevents trailing garbage (CWE-185).
