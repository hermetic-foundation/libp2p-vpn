# Physical Android Public Discovery Check

This read-only check looks for automatic public discovery on Wi-Fi while
Android also has a validated cellular network. It does not verify packet
absence. See [the packet-level acceptance criteria](public-discovery-relay-acceptance.md).

## Before Connecting The Pixel

| Required | Check |
| --- | --- |
| Authorized Pixel, Android 10 or newer | USB debugging authorized; use the device's explicit ADB serial and a data cable |
| Known debug build | Install the agreed build separately. Use the exact single-file APK for the on-device hash check below |
| Running p2p-vpn profile | VPN already enabled; know the test profile name. No concurrent pairing, VPN restart, or test overrides |
| Two physical Internet networks | Normal Wi-Fi is preferred; cellular data remains connected and validated. No USB tethering or other upstream VPN |
| Test traffic | Allow normal automatic public discovery; avoid intentional overlay traffic during the window. Know any configured peer and relay IDs |
| Host | Bash, `adb`, `jq`, and GNU coreutils. Keep the capture directory private |

Having mobile data turned on is not proof that cellular stayed connected.
If Android does not keep both networks validated under normal conditions,
record the test as ineligible. This procedure does not change device settings.

## Capture

Set `SERIAL`, `APK`, and `PROFILE` in Bash. Run this block with the VPN
already active. It records two full boundary samples and one intermediate
ownership sample, over roughly two minutes. It does not trigger discovery.

```bash
(
  set -euo pipefail
  umask 077
  : "${SERIAL:?authorized USB device serial}" "${APK:?known debug APK path}"
  : "${PROFILE:?running overlay profile name}"
  package=org.hermeticfoundation.p2pvpn.debug
  receiver=org.hermeticfoundation.p2pvpn.DebugAutomationReceiver
  ad() { timeout -k 2s 25s adb -s "$SERIAL" "$@"; }
  fail() { printf '%s\n' "$*" >&2; exit 1; }
  [[ $(ad get-state) == device && $(ad get-devpath) == usb:* ]] || fail 'Expected authorized USB ADB'
  api=$(ad shell getprop ro.build.version.sdk)
  [[ $api =~ ^[0-9]+$ && $api -ge 29 ]] || fail 'Expected Android 10 or newer'
  qemu=$(ad shell getprop ro.boot.qemu)
  [[ $qemu != 1 && $SERIAL != emulator-* ]] || fail 'Expected physical device'

  installed=$(ad shell pm path --user 0 "$package")
  installed=${installed#package:}
  [[ $installed =~ ^/data/app/[a-zA-Z0-9/._=+~-]+/base\.apk$ ]] || fail 'Expected a single installed debug APK'
  installed_sha=$(ad shell sha256sum "$installed")
  expected_sha=$(sha256sum < "$APK")
  [[ ${installed_sha%% *} == "${expected_sha%% *}" ]] || fail 'Installed debug APK does not match'
  uid=$(ad shell pm list packages -U --user 0 "$package" |
    awk -v p="package:$package" '$1 == p && $2 ~ /^uid:[0-9]+$/ {print substr($2,5)}')
  [[ $uid =~ ^[0-9]+$ ]] || fail 'Debug app UID not found'

  out=$(mktemp -d -t p2p-vpn-pixel-public.XXXXXXXX)
  printf 'Private evidence: %s\n' "$out"
  printf 'api=%s\napk_sha256=%s\napp_uid=%s\n' "$api" "${expected_sha%% *}" "$uid" > "$out/build"
  ad shell getprop ro.build.fingerprint > "$out/fingerprint"

  rpc() {
    ad shell am broadcast --receiver-foreground \
      -a "$package.AUTOMATION" -n "$package/$receiver" --es command "$@" |
      sed -nE 's/^Broadcast completed: result=[^,]+, data="([A-Za-z0-9+/=]+)".*$/\1/p' |
      base64 --decode | jq -ce 'select(.schema_version == 1 and .ok == true) | .value'
  }

  # Record unsupported/denied dumps separately; cap file size on the host.
  optional() (
    output=$1; shift
    ulimit -f 8192
    if ad "$@" > "$output" 2> "$output.stderr"; then
      printf '0\n' > "$output.exit"
    else
      printf '%s\n' "$?" > "$output.exit"
    fi
  )

  sample() {
    local stage=$1
    ad shell date +%s > "$out/$stage.start-epoch"
    optional "$out/$stage.connectivity" shell dumpsys connectivity
    rpc status | jq -e --arg profile "$PROFILE" '
      select(.service_ready and .snapshot.connected) | .snapshot as $s |
      [$s.networks[] | select(.name == $profile and .enabled and .phase == "running")] as $n |
      select(($n | length) == 1) |
      {network_id: $n[0].id, peer_id: $n[0].peer_id, runtime_generation: $s.runtime_generation, underlay: $s.underlay,
       paths: {public_routing_peers: $s.paths.public_routing_peers}}
    ' > "$out/$stage.status.json"
    local network
    network=$(jq -er '.network_id | select(test("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$"))' \
      "$out/$stage.status.json")
    rpc transport-snapshot --es network_id "$network" | jq -e --arg id "$network" '
      select(.schema_version == 1 and .network_id == $id and
        (.lines | type == "array" and index("daemon state: running") != null))
    ' > "$out/$stage.transport.json"
    if [[ $stage != middle ]]; then
      optional "$out/$stage.links" shell ip -s link show
      optional "$out/$stage.netstats" shell dumpsys netstats --uid --full
    fi
    ad shell date +%s > "$out/$stage.end-epoch"
  }

  sample before
  sleep 60
  sample middle
  sleep 60
  sample after
  jq -es 'all(.[]; .underlay.kind == "wifi" and .underlay.validated == true) and
    (map([.network_id, .peer_id, .runtime_generation, .underlay.selection_changes, .underlay.selected_losses]) |
     unique | length == 1)' "$out"/{before,middle,after}.status.json >/dev/null ||
    fail 'Ineligible: runtime or Wi-Fi underlay changed across samples'
  printf 'Check OS network eligibility and discovery activity in %s\n' "$out"
)
```

## Interpret The Evidence

1. **Confirm eligibility.** At each sample find separate Wi-Fi and cellular
   `NetworkAgentInfo` entries with `INTERNET`, `VALIDATED`, and `NOT_VPN`.
   Record their net IDs, interfaces, addresses, and available routes. Match
   the Wi-Fi default with the app's physical `underlay`, not a VPN agent.
   If the dump exposes only a logical VPN default, do not treat its ID as
   the physical default. Report the app-selected Wi-Fi and any OS ambiguity.
2. **Require positive activity.** Compare the snapshot counters and recent
   history below. For a controlled endpoint, match the server's authenticated
   connection or reservation to the phone Peer ID and observation window.
   If no fresh operation can be attributed to the observed connection,
   report **inconclusive** for that path.
3. **Compare ownership.** For that peer and endpoint, match the snapshot's
   `physical control state:` `connection_id`, `network_handle`, source, and
   interface index to the observed Wi-Fi network. Require a current, available,
   adopted owner for an established dial; don't count stale or unknown rows.
   On current Android, check the handle's low bits before decoding the net ID
   from its upper 32 bits ([AOSP netd implementation](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/NetworkController.h)).
   `interface=` in the snapshot is a numeric index; use `ip -s link show`.
4. **Record corroborating counters.** From each `netstats` dump capture the
   app UID's untagged RX/TX bytes and packets by Wi-Fi and mobile identity,
   keeping bucket times, and record each physical interface's RX/TX bytes and
   packets from `ip -s link`. Mark missing, denied, delayed, or unmatchable
   counters unavailable, not zero. Do not add tagged rows to untagged totals.

| Snapshot signal | Interpretation |
| --- | --- |
| `auto_relay_reservation_attempts` and `auto_relay_reservation_failures` | Runtime-wide counts; an increase shows work, not the relay, socket owner, or transmitted packets |
| `auto_relay_active_reservations` and `relay_infrastructure_peer` | Current reservation count and known relay addresses; useful context, not proof of a new reservation |
| `transport event:` `event=relay_client_limit role=reservation` | New, untruncated sequence plus age identifies a recent accepted reservation and relay ID. Correlate `relay_listen_address_ready`, absence of an explicit relay, and a unique matching live owner; prefer server corroboration |
| `public_routing_peers` and `public_discovery_unverified_addresses_rejected` | Changes show routing inventory or address rejection, not a successful bootstrap or DHT request. Use a controlled server for attribution |

The release-matching debug build does not expose ordinary core discovery
info events in logcat. The snapshot's bounded native event history is separate:
compare event `seq` and `age_millis`, and check for eviction or truncation.
It does not retain `auto_relay_reservation_attempt` events or bind a
reservation event to one exact connection ID.

| Observation | Supported conclusion |
| --- | --- |
| Confirmed automatic operation, matching current Wi-Fi owner | That observed, established automatic connection used the Wi-Fi underlay |
| Confirmed automatic operation, matching current cellular owner while Wi-Fi was preferred | Investigate a policy violation; exclude a member path, configured relay, or an old connection before attributing it |
| Cellular app-UID counters increase | Android attributed app traffic to mobile. The protocol, destination and purpose are unknown |
| Cellular counters unchanged, or no cellular owner sampled | No increase or owner was observed in those sources. This is not a packet-absence result |

Quiet mode, a reused socket, event eviction, or a short-lived attempt can leave
no fresh observable evidence. Don't treat failed dials, encrypted or cached
DNS, or traffic attributed to the system resolver as covered by this check.
Android's [NetworkStats dump](https://android.googlesource.com/platform/frameworks/base/+/3a66bd2809838723252d0b81dfd8d3d2b3da6b23/packages/ConnectivityT/service/src/com/android/server/net/NetworkStatsService.java)
is accounting history, not a live packet tap. Interface counters also include
other apps and OS traffic. Keep raw captures private; redact peer IDs, IPs,
Wi-Fi information and carrier identifiers before publishing results.

## Controlled Endpoint Without An APK Rebuild

For stronger attribution, prepare a known public Kademlia server under the
tester's control with an Internet-routable TCP or QUIC endpoint. For HOP, the
same server can advertise relay service and log accepted reservations. Use
timestamped server output and a seed dedicated to the test.

The existing debug `create-profile` command accepts `bootstrap_peer_id`,
`bootstrap_address`, and `kademlia_protocol=/ipfs/kad/1.0.0`. The emulator
used this hook to supply a controlled seed through the public discovery code.
Do not set `relay_reservation` or add the seed as a member: either would
exercise a different policy. This is not a test of the bundled bootstrap list.

Creating or enabling a profile changes app state and is not part of the
read-only capture above. Only do it with separate approval, using an isolated
test profile. Identify the phone's first authenticated connection in server
logs, then capture the owner while it is live. For a reservation, match the
server's `relay server accepted reservation from <phone-peer-id>` event.
Do not label a server handshake as proof that a particular DHT RPC completed.

## Stronger Packet Proof

Use an authorized rooted test device or a controlled topology that observes
both actual egresses. Match the app UID where possible and a controlled unique
bootstrap/relay address, port and resolver name. Verify the cellular capture
with a positive control before using it to assert absence. A Wi-Fi router
capture alone cannot see packets sent over the carrier network. A stock Pixel
run with no such capture is ownership verification only.
