## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Improper Input Validation using re.match
**Vulnerability:** The `ipAddressCheck` function in `proxydhcpd/proxyconfig.py` used `re.match` for IP validation. `re.match` only checks for a match at the beginning of the string, allowing strings with trailing garbage characters (e.g., "192.168.1.1; echo pwn") to pass validation.
**Learning:** `re.match` does not guarantee that the entire input conforms to the regular expression, leading to incomplete validation and potential bypass of security controls.
**Prevention:** Always use `re.fullmatch` or explicitly anchor regex patterns with `^` and `$` to ensure the entire input string is validated against the desired pattern.
