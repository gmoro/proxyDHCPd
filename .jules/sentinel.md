## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2026-06-06 - CWE-185: Partial Match Vulnerability in IP Validation
**Vulnerability:** `re.match` was used for IP address validation in `proxyconfig.py`, allowing trailing garbage characters to bypass validation because it only checks the beginning of the string.
**Learning:** Python's `re.match` behavior can lead to serious validation bypasses if inputs contain valid prefixes followed by malicious payloads (e.g. command injection).
**Prevention:** Always use `re.fullmatch` for exact string validation rather than `re.match` when the goal is to validate the *entire* input string against a pattern.
