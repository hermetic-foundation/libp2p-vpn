# Linux Route Monitor

## Notification Admission

| Input | Action |
| --- | --- |
| Non-kernel sender | Ignore |
| Kernel multicast link, address, route or rule change | Invalidate the observation generation |
| Kernel unicast response, unmatched reply or successful ACK | Ignore as a change notification |
| Kernel multicast error or receive overrun | Retire the observer; recover with bounded backoff |
| Driver termination or cancelled incomplete lookup | Retire the observer; reject stale results |

Admission uses sender identity and multicast destination groups, not sequence zero.
Real route notifications can retain the originating request's sequence number.
See the kernel's [address notification construction](https://github.com/torvalds/linux/blob/master/net/ipv4/devinet.c)
and [Netlink receive addressing](https://github.com/torvalds/linux/blob/master/net/netlink/af_netlink.c).

## Diagnostics

- Retain only the latest observation kind, message type, sequence, group mask and error code.
- Include that observation and the live generation in stale-route diagnostics.
- Add no polling, per-packet event stream or unbounded event history.

The subscribed groups fit the 32-bit received address mask. A regression guards
that assumption; adding larger group numbers requires packet-info handling.

## Evidence And Limits

| Check | Result |
| --- | --- |
| Route-monitor tests | 16 passed, including real IPv4/IPv6 metric, rule, loss and return changes |
| Native QUIC namespaces | Eight passed: DHT, AutoNAT and configured/automatic relay reservation return |
| Owned QUIC real TUN | Both original roles passed; fixed IPv4 endpoints, two underlays, preference change and return |
| Quiet workspace | 2,456 passed, 87 ignored; local Android integration included, before later TCP error-classification changes |

Two earlier working-tree runs failed after route-bound fixtures were invalidated.
Their initiating cause remains unproven. Passing isolated tests does not prove
that this classifier caused or fixes those earlier failures.
