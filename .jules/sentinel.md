## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Potential Command Injection via Weak IP Regex Validation
**Vulnerability:** The `ipAddressCheck` method in `proxyconfig.py` used `re.match()` to validate IP addresses. `re.match()` only checks for a match at the beginning of a string, allowing trailing garbage characters (e.g., `192.168.1.1; rm -rf /`) to be considered valid IP addresses.
**Learning:** This existed because `re.match()` is commonly misunderstood as checking the entire string. In Python, `re.match()` anchors to the start but doesn't anchor to the end unless `$` or `\Z` is used.
**Prevention:** Always use `re.fullmatch()` when validating the strict format of an entire string (like an IP address or email) to prevent partial matches and potential injection vulnerabilities (CWE-185).
