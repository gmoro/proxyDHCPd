## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Silent Type-Mismatch Bypass in Fixed-Length Option Validation
**Vulnerability:** In `pydhcplib`'s option setting logic (`SetOption`), fixed-length validation inadvertently compared a list (`specs`) to an integer (`length`). Python evaluated this as `False` rather than raising a TypeError, causing the logic to fall through to the variable-length validation check, which inadvertently allowed any length value.
**Learning:** Silent type-mismatches in condition evaluation can entirely disable security or validation checks without any runtime errors, especially when chained with fallback `or` logic.
**Prevention:** Always compare exact array indices (`specs[0] == length`) for primitive validation, and explicitly check preconditions (`specs[0] == 0`) before falling back to alternative validation branches.
