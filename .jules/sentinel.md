## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-06-17 - Partial Match IP Validation Bypass
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, the `ipAddressCheck` function used `re.match` to validate IP addresses. `re.match` only checks if the regex pattern matches the *beginning* of the string, which allowed potentially invalid IPs with trailing garbage characters (e.g. `192.168.1.1 trailing`) to pass validation. This could lead to configuration parsing errors or subtle injection vulnerabilities if the partially-validated input is passed to system commands without further sanitization.
**Learning:** Python's `re.match` is insufficient for strict whole-string validation. Always use `re.fullmatch` when validating fixed-format inputs like IP addresses or hostnames.
**Prevention:** Enforce strict boundary matching using `re.fullmatch` instead of `re.match` or `re.search` for security-sensitive input validation.
