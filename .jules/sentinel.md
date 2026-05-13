## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Partial String Matching in IP Validation
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. `re.match` only checks if the pattern matches at the *beginning* of the string, allowing IP addresses with trailing garbage (like `192.168.1.1.2` or `192.168.1.1xyz`) to be considered valid if the beginning looks like an IP.
**Learning:** `re.match` does not guarantee strict boundary adherence for the entire string even if word boundaries (`\b`) are used at the end of the regex, leading to partial match vulnerabilities (CWE-185).
**Prevention:** Always use `re.fullmatch` instead of `re.match` when strict validation of the entire input string is required.
