## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-27 - Partial Match IP Validation Bypass
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, the `ipAddressCheck` function utilized `re.match` for IP address validation. `re.match` only checks if the regex pattern matches at the *beginning* of the string, which allowed trailing garbage (e.g., `192.168.1.1.2.3` or `192.168.1.1 DROP TABLE`) to pass validation as a valid IP address. This is a CWE-185 vulnerability.
**Learning:** This occurred because `re.match` is often misunderstood as checking the entire string against a pattern, whereas only `re.fullmatch` enforces that the entire string complies with the regular expression.
**Prevention:** Always use `re.fullmatch` (or append `$` to the regex pattern) when performing strict input validation with regular expressions in Python to prevent partial match bypasses.
