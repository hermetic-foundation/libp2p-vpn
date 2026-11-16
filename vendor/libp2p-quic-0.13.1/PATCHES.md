# Local Patch

Base: crates.io `libp2p-quic` 0.13.1, retaining its MIT license and upstream
metadata. This patch adds optional per-connection socket policy and physical
ownership callbacks. Native libp2p TLS, certificate identity verification, QUIC
wire bytes, stream multiplexing, and existing transport APIs are retained.
It is separate from the application's owned QUIC packet plane.

## Additive Policy APIs

The following types are exported from the crate root.

| API | Contract |
| --- | --- |
| `Config::with_socket_policy(self, Arc<dyn SocketPolicy>) -> Self` | Opt into policy before constructing the transport |
| `SocketContext { local: SocketAddr, remote: SocketAddr, role: Endpoint, mark: u32 }` | Actual shared socket address/port, remote destination, preparation role, and socket mark; incoming preparation substitutes the received destination IP into `local` |
| `SocketPolicy::prepare(&self, SocketContext) -> BoxFuture<'static, io::Result<Selection>>` | Asynchronously select egress and create its ownership sidecar before connection handshaking |
| `Selection { source: IpAddr, interface: NonZeroU32, owner: Box<dyn ConnectionOwner> }` | Immutable transmit selection plus caller-owned route/lifetime state |
| `ConnectionOwner::before_handshake(&self) -> io::Result<()>` | Reject stale selection immediately before a handshake or each managed hole-punch probe |
| `ConnectionOwner::authenticated(&mut self, PeerId) -> io::Result<()>` | Associate the exact peer authenticated by the existing native TLS engine |
| `ConnectionOwner::admitted(&mut self, usize) -> io::Result<()>` | Associate the exact process-local swarm CID after swarm admission |

`SocketPolicy` and `ConnectionOwner` require `Debug + Send + Sync + 'static`.
They do not define routing preference themselves. The caller supplies kernel
route selection, generation validation, preparation budgets, and RAII cleanup.
Linux/Android contexts read `SO_MARK`; other platforms report zero and still
require a Quinn backend capable of enforcing interface selection.

## Default Compatibility And Socket Ownership

`Config::new` installs no policy. Unmanaged dialers keep their original socket
descriptor footprint: `SocketEndpoint.socket` is `None`, and `bound_socket`
does not clone an observation FD. Managed dialers retain an observation clone
only when policy is installed. Listener reuse shares its existing socket via
`Arc`; it does not duplicate an FD for each connection.

Unmanaged connection setup, listener acceptance, and raw hole punching retain
their original paths. Installing policy does not rebind a shared endpoint,
change its receive filtering, or close sibling connections. Existing port-reuse
and dial-as-listener branches remain in place. There are no new user-facing
configuration fields or maintenance timers.

## Preparation And Authentication

| Stage | Managed behavior |
| --- | --- |
| Outgoing preparation | Observe the chosen existing endpoint's real local port and mark, then await `prepare` |
| Before TLS | Recheck the observation socket's local tuple and mark, then call `before_handshake` |
| Outgoing start | Call patched Quinn `Endpoint::connect_with_on_interface(config, remote, server_name, source, interface)` on that same endpoint |
| Incoming preparation | Read `Incoming::local_ip` and remote address; await policy before calling Quinn acceptance |
| Incoming start | Require canonical selected source equality with the received destination, then call `Incoming::accept_on_interface` |
| TLS completion | Parse the verified native libp2p certificate identity and call `authenticated` before returning the muxer |
| Swarm admission | The patched core/swarm muxer hook delivers the actual CID to `admitted`; no endpoint, tuple, FIFO, or display-string inference |

Prepared connection setup is bounded by the existing handshake timeout,
including time spent awaiting policy. Quinn validates source/family, explicit
source binding, interface range, and backend support before starting a selected
outgoing connection. Its connection state retains selection for initial,
buffered, retransmitted, application, and close traffic without an unselected
retry. Incoming selection retains the source used to reach the shared listener.

`authenticated` proves the peer that TLS actually verified, not that a requested
peer or swarm admission has already succeeded. Wrong-peer and behaviour-denied
connections do not reach `admitted`. Ownership travels with the connection;
normal failure, cancellation, and drop release the caller's sidecar. Callback
failure during authentication or admission closes that connection, not the
whole endpoint or peer.

## Incoming Cancellation And Hole Punching

Managed incoming upgrades own `SelectedIncoming` before their async body is
polled. Dropping an unpolled upgrade, canceling preparation, timing out, or
rejecting selection calls `Incoming::ignore`, not an unselected refusal. This
does not claim to intercept every stateless packet generated inside Quinn
before an application receives an `Incoming`.

Managed hole punching awaits policy once and rechecks socket context and owner
validity before each probe. It uses patched Quinn
`Endpoint::send_on_interface(contents, remote, source, interface)` on the same
shared endpoint and port. Probes retain the existing random 64-byte payload,
10-200 ms jitter, and overall handshake deadline. `WouldBlock` skips that send
and waits for the next jitter tick; no blocking write or unselected retry is
introduced. Successful incoming completion owns its own prepared incoming
selection, independently of the probe's temporary sidecar.

Canceled hole-punch senders are removed during ordinary transport polling and
before registering another dial-as-listener attempt. Live attempts remain;
cleanup neither requires another probe nor creates a cleanup timer. The native
regression covers canceled entries interleaved with live receivers.

## Verification And Limits

| Check | Current record and scope |
| --- | --- |
| Standalone native library suite | 5 passed, including canceled-sender cleanup and unmanaged dialer observation-FD absence; listener/address and dialer lifecycle tests use default transport configuration |

The standalone harness manifest directly targets the unchanged production
`src/lib.rs` and uses a scratch copy of the root lockfile with cached dependencies.
It patches core, swarm, Quinn, and quinn-udp to repository sources; swarm is
unused by this library-only graph. The scratch manifest explicitly enables
`socket2/all` for `SO_MARK`, and Tokio plus identity-generation test features.
No source rewriting, downloads, or test weakening was required.

The command runs `--features tokio --lib`, not upstream integration/QuickCheck
smoke tests, stream-compliance tests, or the complete root dependency graph.
The separate Quinn selected-egress harness is not this native library suite.
Application ownership and physical namespace migration are separate integration
checks, not certified by these five library tests.

These checks do not prove complete DHT/AutoNAT/relay migration, physical IPv6
return, hole-punch interoperability on every NAT, Android device behavior, or
battery improvement. Native server-side QUIC address migration remains disabled;
preferred return uses separately validated replacement connections and must
preserve required incoming owners until their retirement is safe.
