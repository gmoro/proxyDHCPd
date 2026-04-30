## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-25 - Partial IP Matching Vulnerability
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` which only matches the beginning of a string. This allowed trailing garbage characters, including potential shell metacharacters (e.g., `192.168.1.1; rm -rf /`), to be considered a valid IP address.
**Learning:** `re.match` does not enforce that the entire string matches the pattern, leading to CWE-185 (Incorrect Regular Expression).
**Prevention:** Always use `re.fullmatch` for strict validation to ensure the entire input string conforms to the expected pattern, preventing bypass via trailing characters.
