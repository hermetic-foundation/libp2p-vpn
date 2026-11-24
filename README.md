<p align="center">
  <img src="assets/p2p-vpn-logo.svg" alt="p2p-vpn mesh logo" width="180">
</p>

# libp2p-vpn

`libp2p-vpn` is the Rust SDK for a libp2p-native mesh VPN. This repository
owns the runtime, protocol, platform adapters, and reusable fixtures.
The native CLI, NixOS deployment, and release archives belong to
the [p2p-vpn application](https://github.com/hermetic-foundation/p2p-vpn).

It uses libp2p for identity, encrypted transports, discovery, relay, AutoNAT,
and DCUtR. It forwards overlay IP packets through authenticated packet
protocols and bounded queues.

## Documentation

| Audience | Start Here | Purpose |
| --- | --- | --- |
| SDK developers | [Developer Guide](docs/developer/README.md) | Architecture, tests, and debugging. |
| App users | [p2p-vpn](https://github.com/hermetic-foundation/p2p-vpn) | Install and run a VPN node. |

## Quick Links

- [Android](docs/user/android.md)
- [Windows](docs/user/windows.md)
- [Browser WebAssembly](docs/user/browser.md)
- [Pairing](docs/user/pairing.md)
- [Network Membership](docs/user/membership.md)
- [Overlay DNS](docs/user/dns.md)
- [Configuration](docs/user/configuration.md)
- [Operations](docs/user/operations.md)
- [Public libp2p/IPFS Reachability](docs/user/public-libp2p.md)
- [Architecture](docs/developer/architecture.md)
- [Feature Matrix](docs/developer/feature-matrix.md)
- [Testing](docs/developer/testing.md)
- [Network Debugging](docs/developer/network-debugging.md)

## Build

Build the Rust library:

```sh
cargo build --locked --lib
```

The default Nix package builds and tests the library and installs its Rust
artifact. Cargo applications should depend on the SDK crate, not link the
Nix-built artifact directly. See [native embedding](examples/native_embedding.rs).

On `x86_64-linux`, build the reusable Android or browser bindings:

```sh
nix build .#android-aar
nix build .#browser-sdk
```

See the [embedding guide](docs/developer/extraction.md) for integration and
verification commands.

## Fast Verification

```sh
nix run .#check-fast
```
