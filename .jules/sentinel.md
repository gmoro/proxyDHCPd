## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Input Validation Bypass via Partial Regex Matching
**Vulnerability:** The `ipAddressCheck` in `proxyconfig.py` used `re.match` which checks for a match only at the beginning of the string. This allowed potentially malicious strings like `"192.168.1.1\nmalicious"` or `"192.168.1.1; rm -rf /"` to pass IP validation since the prefix matched a valid IP address.
**Learning:** `re.match` is insufficient for strict input validation because it ignores trailing garbage characters. This is a common pattern for injection vulnerabilities if the validated string is later used in shell commands or logs.
**Prevention:** Always use `re.fullmatch` for strict string validation when verifying that an entire input conforms to a specific format (e.g. an IP address).
