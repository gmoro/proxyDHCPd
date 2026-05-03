## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - DoS/Injection via Weak IP Address Regex Validation
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match()` instead of `re.fullmatch()` to validate IP addresses. `re.match()` only checks for a match at the *beginning* of the string, allowing potentially malicious trailing characters (e.g., `192.168.1.1/24`, `192.168.1.1;rm -rf /`) to pass validation and be processed as valid IP addresses.
**Learning:** This existed because of a common misunderstanding in Python's `re` module where `re.match` is assumed to match the entire string like it does in some other languages or frameworks.
**Prevention:** When validating security-critical input strings (like IP addresses, domains, or filenames) with regex in Python, always use `re.fullmatch()` to ensure the entire string conforms to the pattern, preventing partial matches with malicious payloads.
