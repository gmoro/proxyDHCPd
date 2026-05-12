## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2025-05-24 - Partial Matches with `re.match` (CWE-185)
**Vulnerability:** The configuration parsing code for IP addresses (`ipAddressCheck` in `proxydhcpd/proxyconfig.py`) used `re.match()` rather than `re.fullmatch()`. Because `re.match()` only requires the pattern to match the *beginning* of the string, it could accept malicious strings containing valid IP prefixes followed by invalid or injected characters (e.g., `192.168.1.1\nfoobar`).
**Learning:** This is a common pitfall in Python when using standard library regex functions; developers often confuse `match` (starts with) with `fullmatch` (entire string).
**Prevention:** Always use `re.fullmatch` (or wrap patterns in `^...$`) when strictly validating the entirety of user or configuration inputs.
