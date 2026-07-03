## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-07-03 - Strict Regex Validation
**Vulnerability:** Use of `re.match` for IP address validation allowed partial matches with trailing garbage characters (CWE-185).
**Learning:** `re.match` only checks if the pattern matches at the beginning of the string, allowing bypassing of strict validation if the input is malicious.
**Prevention:** Always use `re.fullmatch` for strict validation of entire strings to prevent partial matches.
