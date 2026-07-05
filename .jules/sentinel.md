## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Incorrect Regular Expression Validation for IP Addresses
**Vulnerability:** The `ipAddressCheck` method in `proxydhcpd/proxyconfig.py` used `re.match` to validate IP addresses. Because `re.match` only checks if the beginning of the string matches the pattern, it permitted trailing garbage (e.g., `"192.168.1.1 trailing garbage"` would incorrectly pass).
**Learning:** This vulnerability existed due to a misunderstanding of Python's `re` module, where `re.match` differs from `re.fullmatch`.
**Prevention:** Always use `re.fullmatch` when validating strictly formatted strings like IP addresses or URLs to ensure the entire string matches the expected pattern.
