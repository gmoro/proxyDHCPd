## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Partial Matching Bypass Vulnerability in Regex Validation
**Vulnerability:** The `ipAddressCheck` function used `re.match` to validate IP addresses. `re.match` only checks for a match at the beginning of the string. This means an input like `192.168.1.1 drop tables` would be incorrectly validated as true, creating an injection risk or logic bypass.
**Learning:** This existed because `re.match` is often misunderstood as validating the entire string.
**Prevention:** Always use `re.fullmatch` when validating the format of an entire string against a regex pattern to ensure there are no trailing garbage characters (CWE-185).
