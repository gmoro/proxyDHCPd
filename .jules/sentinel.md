## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Network Option Fixed-Length Type-Mismatch Bypass
**Vulnerability:** In `pydhcplib`'s option setter (`DhcpBasicPacket.SetOption`), validating a fixed-length field used `specs==length`. Since `specs` is a tuple and `length` is an integer, this condition quietly evaluated to False, causing the validator to fall back to the variable-length validation branch `(specs[1]<=length and length%specs[2]==0)` and permitting excessively long malicious buffers to overwrite memory bounds.
**Learning:** Python will quietly return False for tuple-to-integer equality checks instead of raising a `TypeError`, meaning naive array assertions against raw inputs in protocol parsing logic will silently bypass exact length protections.
**Prevention:** Always compare scalars to scalars when validating parsed protocol constraints; e.g. explicitly checking `specs[0] == length`.
