## 2024-05-24 - DoS via Unhandled Out-Of-Bounds Exception in Packet Parsing
**Vulnerability:** In `pydhcplib`'s packet parsing logic, `DecodePacket` did not check if the iterator was at the end of the packet data before attempting to read the length byte of a DHCP option (`iterator+1`). A specially crafted packet terminating exactly at an option byte code would throw an `IndexError: list index out of range`, potentially crashing the ProxyDHCP daemon handling the packet.
**Learning:** This existed because the original `pydhcplib` codebase assumed a well-formed network payload and blindly relied on `self.packet_data[iterator+1]`.
**Prevention:** Ensure all binary network data parsing functions bounds-check their read iterators against the maximum buffer length before consuming dynamically-sized tokens.

## 2024-05-24 - Validation Bypass via Silent Type Mismatch in DHCP Option Lengths
**Vulnerability:** In `pydhcplib`'s `SetOption`, the length validation logic compared a list `specs` to an integer `length` (`specs==length`). Python evaluates this to `False` without error, causing the strict fixed-length check to fail and execution to fall through to the less strict variable-length validation branch, allowing arbitrary-length data into fixed-length network fields.
**Learning:** This existed because Python silently allows comparisons between different types (list and int) rather than raising a TypeError, hiding the logic bug.
**Prevention:** Always compare scalar values (e.g., `specs[0] == length`) when validating fixed-length constraints and write unit tests that explicitly test boundary conditions of validation rules.
