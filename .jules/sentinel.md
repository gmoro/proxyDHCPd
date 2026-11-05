## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.
## 2024-05-24 - Bug via Silent Type Mismatch in Length Constraints
**Vulnerability:** In `pydhcplib`'s `SetOption` method, comparing a list of constraints (`specs`) to an integer length (`specs==length`) silently evaluated to `False` without raising an error. This caused fixed-length fields to fall through to the less strict variable-length validation branch.
**Learning:** Python allows equality comparisons between different types (like list and int) without raising a TypeError, which can mask logic flaws in critical validation code.
**Prevention:** Ensure correct list indexing (e.g., `specs[0] == length`) is used when validating protocol field constraints, and always explicitly check precondition states (like `specs[0] == 0`) before falling back to variable-length rules.
