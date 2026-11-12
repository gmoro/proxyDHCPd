## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-11-12 - Validation Bypass via Type Mismatch in Option Length
**Vulnerability:** `SetOption` in `dhcp_basic_packet.py` compared a list (`specs`) to an integer (`length`) when validating fixed-length DHCP options. In Python, this evaluates to `False` rather than raising a TypeError, causing the logic to fall through to the variable-length validation branch. As a result, fixed-length options could be supplied with arbitrary lengths.
**Learning:** This existed because Python's dynamic typing and truthiness rules silently fail safe (return False) on type mismatch comparisons, masking the logic error `specs==length` instead of `specs[0]==length`.
**Prevention:** Always explicitly test specific tuple/list indices or unpack variables when comparing against scalar values in validation functions.
