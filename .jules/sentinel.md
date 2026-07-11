## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Strict Regex Validation for IP Addresses (CWE-185)
**Vulnerability:** The application used `re.match` to validate IP addresses from user input (config files). `re.match` only checks if the pattern matches at the *beginning* of the string, allowing partial matches like `192.168.1.1 trailing_garbage` to pass validation if they start with a valid IP.
**Learning:** `re.match` is insufficient for strict input validation, as it does not enforce that the entire string matches the pattern, which can lead to injection attacks or processing of malformed data.
**Prevention:** Always use `re.fullmatch` for input validation to ensure the entire input string conforms to the expected pattern, adhering to CWE-185 (Incorrect Regular Expression).
