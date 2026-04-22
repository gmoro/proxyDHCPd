## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Bypass in IP Address Validation
**Vulnerability:** The `ipAddressCheck` in `proxydhcpd/proxyconfig.py` used `re.match` which only enforces a match at the beginning of a string. An input such as `"192.168.1.1; rm -rf /"` passes validation but introduces a potential command injection risk if used in shell execution later.
**Learning:** `re.match` is insecure for full-string validation as it allows trailing garbage characters.
**Prevention:** Always use `re.fullmatch` for strict validation requirements in Python standard library regular expressions, or anchor the expression using `^` and `$`.
