## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-25 - Partial Pattern Match allows Malicious Input
**Vulnerability:** In `proxydhcpd/proxyconfig.py`, the `ipAddressCheck` method used `re.match()` to validate IP addresses. Because `re.match()` only checks for a match at the *beginning* of the string, it allowed input with trailing garbage or shell metacharacters (e.g. `192.168.1.1; echo exploit`) to pass validation.
**Learning:** This existed because `re.match()` is often mistakenly assumed to match the entire string like standard regex implementations in other languages, whereas Python requires explicit boundary anchors or `re.fullmatch()`.
**Prevention:** When validating security-sensitive configuration strings, especially IPs or hostnames, always use `re.fullmatch()` rather than `re.match()` to ensure strict, end-to-end string matching.
