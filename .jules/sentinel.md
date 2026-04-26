## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - [CWE-185] Weak IP Address Validation using re.match
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` which only checks the beginning of the string, allowing partial matches with trailing garbage characters (e.g., `192.168.1.1; rm -rf /`).
**Learning:** `re.match` is insufficient for strict input validation because it succeeds even if only the start of the string matches the pattern. This can lead to injection vulnerabilities if the validated input is later used in shell commands or SQL queries.
**Prevention:** Always use `re.fullmatch` for strict validation, or append `$` to the regular expression pattern to ensure the entire string matches.
