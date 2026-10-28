## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Silent Bypass in Fixed-Length Option Validation
**Vulnerability:** In `SetOption` of `pydhcplib`, comparing the tuple/list `specs` to an integer `length` evaluated to False silently. This caused the logic to fall through to the variable-length validation branch, allowing fixed-length options to be set with arbitrary lengths.
**Learning:** Python silently ignores type mismatches in equality comparisons without throwing an exception, which can easily create silent validation bypasses.
**Prevention:** Explicitly access the list index (`specs[0]`) when comparing fixed lengths, and ensure mutually exclusive logic branches use exact predicates (e.g., `specs[0]==0`).
