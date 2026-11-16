# Local Patch

- Base: crates.io `libp2p-relay` 0.21.1; unchanged wire protocol and event types.
- Archive SHA-256: `d8b9b0392ed623243ad298326b9f806d51191829ac7585cc825c54c6c67b04d9`.
- Expose confirmed reservation connection IDs from the existing native maps.
- Allow selection of an authenticated direct connection for future reservations and circuits.
- Keep existing reservation/circuit/renewal ownership and default selection unchanged.
- Track exact reservation, dispatcher, codec and circuit dependencies with RAII leases beside native connection records.
- Bind real listener requests to exact direct connections; closed listeners cannot dispatch queued work.
- Drain reservation renewals and reservation-only keepalive against a confirmed replacement without closing circuits or listeners.
- Preserve a shared advertised address when another confirmed, non-draining owner remains.
- No wire changes, transport engine, extra maintenance timer, or user-managed route configuration.
- Regression coverage: repository `tests/relay_ownership.rs`, `tests/relay_connection_dependencies.rs`, and `tests/relay_reservation_drain.rs`.
