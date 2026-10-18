## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Type Mismatch Bypass in Fixed-Length Option Validation
**Vulnerability:** In `pydhcplib`'s `SetOption` method, fixed-length DHCP options (like `subnet_mask`) allowed any payload length. The code compared the tuple `specs` directly to the integer `length` (`specs==length`), which evaluated to `False` without an error. This caused the logic to fall through to the less strict variable-length validation branch.
**Learning:** This existed because Python quietly evaluates tuple-to-integer comparisons as `False` rather than raising a type error, allowing the validation fallback `or (specs[1]<=length ...)` to apply universally.
**Prevention:** Always extract the specific index of a tuple (e.g., `specs[0]`) when comparing against an integer in validation logic, and enforce mutually exclusive validation branches (e.g., checking `specs[0]==0` for variable lengths).
