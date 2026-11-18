#!/usr/bin/env bash
set -euo pipefail
umask 077

# A synthetic IPv4 address is mapped inside the disposable guest to its host
# alias. The host forwards bytes over a Unix socket into the relay namespace.
# The relay still terminates separate TCPv4 and TCPv6 connections itself.
v4=11.252.0.254
v6=2001:db9:252::fe
listen_port=42200
package=org.hermeticfoundation.p2pvpn.debug
java_package=org.hermeticfoundation.p2pvpn

wait_file() {
  for ((i=0; i<$3; i++)); do
    [[ ! -e "$1" ]] || return 0
    kill -0 "$2"
    sleep 1
  done
  echo "Timed out waiting for $1" >&2
  return 1
}

stop_children() {
  local pid
  for pid; do kill -TERM "$pid" 2>/dev/null || true; done
  for pid; do wait "$pid" 2>/dev/null || true; done
}

if [[ "${1:-}" == --namespace ]]; then
  work="$2"
  vpn="$3"
  children=()
  trap 'stop_children "${children[@]}"' EXIT
  trap 'exit 143' TERM
  trap 'exit 130' INT
  ip link set lo up
  # The child shell expands its own positional arguments.
  # shellcheck disable=SC2016
  unshare -n -- bash -ec '
    ip link set lo up
    touch "$1/member-net"
    while [[ ! -e "$1/start-linux" ]]; do sleep 0.2; done
    exec "$2" up --config "$1/linux.json" --control-socket "$1/member.sock"
  ' bash "$work" "$vpn" >"$work/linux.log" 2>&1 &
  member=$!
  children+=("$member")
  wait_file "$work/member-net" "$member" 10
  ip link add relay-v6 type veth peer name member-v6
  ip link set member-v6 netns "$member"
  ip addr add "$v6/64" dev relay-v6 nodad
  ip link set relay-v6 up
  nsenter -t "$member" -n ip addr add 2001:db9:252::1/64 dev member-v6 nodad
  nsenter -t "$member" -n ip link set member-v6 up
  nsenter -t "$member" -n ip -6 route add default via "$v6"
  if nsenter -t "$member" -n ip -4 route get "$v4" >/dev/null 2>&1; then
    echo "Linux fixture has an unexpected IPv4 route" >&2
    exit 1
  fi
  printf '%s\n' "$member" >"$work/member.pid"
  "$vpn" up --config "$work/relay.json" --control-socket "$work/relay.sock" &
  children+=("$!")
  python3 "$work/forward.py" unix "$work/forward.sock" "$listen_port" &
  children+=("$!")
  wait "${children[1]}"
  exit 1
fi

if [[ "$#" != 5 || ( "$1" != android-reserves && "$1" != linux-reserves ) ]]; then
  echo "Usage: bash $0 android-reserves|linux-reserves APP_APK TEST_APK EMULATOR_LAUNCHER P2P_VPN" >&2
  exit 2
fi
role="$1"
app="$2"
test_apk="$3"
launcher="$4"
vpn="$(realpath "$5")"
script="$(realpath "$0")"
for command in adb ip jq nsenter python3 ss timeout unshare; do
  command -v "$command" >/dev/null || { echo "Missing fixture dependency: $command" >&2; exit 2; }
done
devices="$(adb devices -l)"
if grep -q '^emulator-' <<<"$devices"; then
  echo "Stop existing emulators before running this isolated fixture" >&2
  exit 2
fi
work="$(mktemp -d /tmp/p2p-vpn-cross-family.XXXXXX)"
echo "Cross-family evidence: $work"
sha256sum "$app" "$test_apk" "$vpn" >"$work/input-checksums"
children=()
cleanup() {
  local status=$?
  if [[ -n "${serial:-}" ]]; then
    ad logcat -d -v epoch -s 'p2p-vpn:I' 'P2pVpnAutomation:W' '*:S' >"$work/android.log" 2>&1 || true
  fi
  stop_children "${children[@]}"
  rm -f "$work"/{android,linux,relay,android-base,linux-base}.json
  return "$status"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT

# The forwarding helper is local to this fixture; it never accepts non-loopback
# host clients or maps between IP address families.
tee "$work/forward.py" >/dev/null <<'PY'
import asyncio
import sys

async def copy(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    writer.write_eof()

async def main(mode, socket, port):
    async def forward(reader, writer):
        remote_writer = None
        try:
            if mode == 'unix':
                remote_reader, remote_writer = await asyncio.open_connection('127.0.0.1', int(port))
            else:
                remote_reader, remote_writer = await asyncio.open_unix_connection(socket)
            async with asyncio.TaskGroup() as streams:
                streams.create_task(copy(reader, remote_writer))
                streams.create_task(copy(remote_reader, writer))
        finally:
            writer.close()
            if remote_writer is not None:
                remote_writer.close()

    if mode == 'unix':
        server = await asyncio.start_unix_server(forward, socket)
    else:
        server = await asyncio.start_server(forward, '127.0.0.1', 0)
        print(server.sockets[0].getsockname()[1], flush=True)
    async with server:
        await server.serve_forever()

asyncio.run(main(*sys.argv[1:]))
PY
python3 "$work/forward.py" tcp "$work/forward.sock" 0 >"$work/port" 2>"$work/forward.log" &
children+=("$!")
for ((i=0; i<10; i++)); do
  [[ ! -s "$work/port" ]] || break
  kill -0 "${children[0]}"
  sleep 1
done
read -r port <"$work/port"
[[ "$port" =~ ^[0-9]+$ ]]

options=(--network android-cross-family --kademlia-protocol /p2p-vpn/kad/1
  --disable-mdns --disable-dcutr --disable-autonat --auto-relay-retry-interval-seconds 5)
entrance4="/ip4/$v4/tcp/$port"
entrance6="/ip6/$v6/tcp/$listen_port"
"$vpn" init-config "${options[@]}" --relay-server --disable-kademlia-provider-advertisement \
  --listen-address "/ip4/127.0.0.1/tcp/$listen_port" --listen-address "$entrance6" \
  --external-address "$entrance4" --external-address "$entrance6" --output "$work/relay.json"
for node in android linux; do
  "$vpn" init-config "${options[@]}" --output "$work/$node-base.json"
done
id() { "$vpn" identity-public --config "$work/$1.json" | jq -er '.peer_id'; }
relay_id="$(id relay)"
android_id="$(id android-base)"
linux_id="$(id linux-base)"
member_config() {
  local node="$1" peer="$2" entrance="$3"
  jq --arg peer "$peer" --arg relay "$relay_id" --arg entrance "$entrance" \
    --argjson reserve "$([[ "$role" == "$node-reserves" ]] && echo 1 || echo 0)" '
    .peers = [{id:$peer}] |
    .network.listen_addresses = [] |
    .network.bootstrap_peers = [{id:$relay,address:$entrance}] |
    .network.discovery.kademlia_provider_advertisement = ($reserve == 1) |
    .network.relay.auto.max_candidates = $reserve |
    .network.relay.auto.max_reservations = $reserve
  ' "$work/$node-base.json" >"$work/$node.json"
}
member_config android "$linux_id" "$entrance4"
member_config linux "$android_id" "$entrance6"
unshare -Urn -- bash "$script" --namespace "$work" "$vpn" >"$work/relay.log" 2>&1 &
children+=("$!")
wait_file "$work/relay.sock" "$!" 25

P2P_VPN_ANDROID_EMULATOR_READY_FILE="$work/ready" "$launcher" >"$work/emulator.log" 2>&1 &
children+=("$!")
wait_file "$work/ready" "$!" 180
read -r serial <"$work/ready" || [[ -n "$serial" ]]
[[ "$serial" =~ ^emulator-[0-9]+$ ]]
ad() { timeout 30 adb -s "$serial" "$@"; }
rpc() {
  local command="$1"
  shift
  ad shell am broadcast --receiver-foreground -a "$package.AUTOMATION" \
    -n "$package/$java_package.DebugAutomationReceiver" --es command "$command" "$@" |
    sed -n 's/.*data="\([A-Za-z0-9+/=]*\)".*/\1/p' | base64 -d | jq -ec 'select(.ok) | .value'
}
ad install -r "$app"
ad install "$test_apk"
ad shell svc data disable
uid="$(ad shell cmd package list packages -U "$package" | tr -d '\r' |
  awk -v package="package:$package" '$1 == package { sub(/^uid:/, "", $2); print $2 }')"
[[ "$uid" =~ ^[0-9]+$ ]]
ad shell su 0 iptables -w -t nat -I OUTPUT -m owner --uid-owner "$uid" \
  -d "$v4" -p tcp --dport "$port" -j DNAT --to-destination "10.0.2.2:$port"
ad shell su 0 iptables -w -N P2PVPN_CROSS_FAMILY
ad shell su 0 iptables -w -A P2PVPN_CROSS_FAMILY -o lo -j RETURN
ad shell su 0 iptables -w -A P2PVPN_CROSS_FAMILY -o wlan0 -d 10.0.2.2 -p tcp --dport "$port" -j RETURN
ad shell su 0 iptables -w -A P2PVPN_CROSS_FAMILY -j REJECT
ad shell su 0 iptables -w -I OUTPUT -m owner --uid-owner "$uid" -j P2PVPN_CROSS_FAMILY
ad shell su 0 ip6tables -w -I OUTPUT -m owner --uid-owner "$uid" '!' -o lo -j REJECT
ad shell -T "run-as $package sh -c 'mkdir -p cache && umask 077 && tee cache/relay-fixture.json >/dev/null'" <"$work/android.json"
ad shell am instrument -w -r -e isolated_emulator true -e seed_relay_profile true \
  "$package.test/$java_package.ServiceLifecycleInstrumentation" | tee "$work/instrumentation.log"
grep -Fq 'INSTRUMENTATION_RESULT: passed=true' "$work/instrumentation.log"
ad shell appops set "$package" ACTIVATE_VPN allow

start_android() {
  local network
  ad shell am start -n "$package/$java_package.MainActivity"
  for ((i=0; i<30; i++)); do
    if rpc status | jq -e '.snapshot.profile_stored == true' >/dev/null; then break; fi
    sleep 1
  done
  network="$(rpc status | jq -er --arg id "$android_id" '
    .snapshot.networks[] | select(.name == "android-cross-family" and .peer_id == $id) | .id')"
  rpc set-network-enabled --es network_id "$network" --ez enabled true | jq -e '.accepted'
  rpc connect | jq -e '.accepted'
  for ((i=0; i<30; i++)); do
    if rpc status | jq -e '.snapshot.connected == true' >/dev/null; then return 0; fi
    sleep 1
  done
  rpc status >"$work/android-start-failed.json"
  echo "Android VPN did not connect" >&2
  return 1
}
start_linux() {
  touch "$work/start-linux"
  wait_file "$work/member.sock" "${children[1]}" 25
}
if [[ "$role" == android-reserves ]]; then
  start_android
  reserver="$android_id"
  caller="$linux_id"
else
  start_linux
  reserver="$linux_id"
  caller="$android_id"
fi
reservation="relay server accepted reservation from $reserver renewed=false"
for ((i=0; i<70; i++)); do
  if grep -Fq "$reservation" "$work/relay.log"; then break; fi
  sleep 1
done
grep -F "$reservation" "$work/relay.log" | sed -n '1p'
if [[ "$role" == android-reserves ]]; then start_linux; else start_android; fi

overlay() {
  "$vpn" up --dry-run --config "$work/$1.json" | awk -v key="address$2:" '$1 == key {sub(/\/.*/, "", $2); print $2}'
}
member_pid="$(<"$work/member.pid")"
android4="$(overlay android 4)"
# The IPv6 addresses are used indirectly by the family loop below.
# shellcheck disable=SC2034
android6="$(overlay android 6)"
linux4="$(overlay linux 4)"
# shellcheck disable=SC2034
linux6="$(overlay linux 6)"
linux_ping() { nsenter -t "$member_pid" -U -n --preserve-credentials ping "$@"; }
android_ping() {
  case "$1" in
    -4) shift; ad shell ping "$@" ;;
    -6) shift; ad shell ping6 "$@" ;;
    *) ad shell ping "$@" ;;
  esac
}
if [[ "$role" == android-reserves ]]; then demand=(linux_ping "$android4"); else demand=(android_ping "$linux4"); fi
for ((i=0; i<45; i++)); do
  if "${demand[0]}" -c 1 -W 1 "${demand[1]}" >/dev/null 2>&1; then break; fi
  (( i < 44 )) || { echo "Caller did not reach the reserver" >&2; exit 1; }
  sleep 1
done
for family in 4 6; do
  a="android$family"
  l="linux$family"
  linux_ping "-$family" -c 5 -W 2 "${!a}" | tee "$work/linux-to-android-v$family.log"
  android_ping "-$family" -c 5 -W 2 "${!l}" | tee "$work/android-to-linux-v$family.log"
  grep -Eq '5 packets transmitted, 5 (packets )?received' "$work/linux-to-android-v$family.log"
  grep -Eq '5 packets transmitted, 5 (packets )?received' "$work/android-to-linux-v$family.log"
done

network="$(rpc status | jq -er '.snapshot.networks[] | select(.name == "android-cross-family") | .id')"
rpc transport-snapshot --es network_id "$network" | jq -er '.lines[]' >"$work/android.state"
"$vpn" daemon-state --socket "$work/member.sock" >"$work/linux.state"
ad shell su 0 iptables -w -nvx -L P2PVPN_CROSS_FAMILY >"$work/android-ipv4-firewall.log"
ad shell su 0 ip6tables -w -nvx -L OUTPUT >"$work/android-ipv6-firewall.log"
nsenter -t "${children[1]}" -U -n --preserve-credentials ss -4Htn state established \
  "sport = :$listen_port" >"$work/relay-tcp4.sockets"
nsenter -t "${children[1]}" -U -n --preserve-credentials ss -6Htn state established \
  "sport = :$listen_port" >"$work/relay-tcp6.sockets"
check_state() {
  local node="$1" peer="$2" entrance="$3"
  awk -v peer="$peer" -v relay="$relay_id" -v entrance="$entrance" '
    /^peer state:/ && index($0, " transport " peer " ") && / validated true / &&
      / selected_path circuit_relay / && / direct_paths 0 / {
        for (i=1; i<NF; i++) if ($i == "selected_path_connection_id") selected=$(i+1)
    }
    /^physical circuit state:/ && $4 == "peer=" peer && $6 == "relay=" relay &&
      index($0, " outer_remote=" entrance "/p2p/" relay " ") && / outer_usable=true / && / inner_usable=true / {
        split($5, connection, "=")
        usable[connection[2]]=1
    }
    $1 == "outbound_relay_stream_fallback_packets" && $2 >= 20 { relayed=1 }
    /^outbound_direct_.*packets / && $2 > 0 { direct=1 }
    END { exit !(selected in usable && relayed && !direct) }
  ' "$work/$node.state"
}
grep -F "relay server accepted circuit $caller -> $reserver" "$work/relay.log" | sed -n '1p'
grep -Fq "127.0.0.1:$listen_port" "$work/relay-tcp4.sockets"
grep -Fq "[$v6]:$listen_port" "$work/relay-tcp6.sockets"
check_state android "$linux_id" "$entrance4" || { echo "Android circuit assertions failed" >&2; exit 1; }
check_state linux "$android_id" "$entrance6" || { echo "Linux circuit assertions failed" >&2; exit 1; }
printf 'PASS: %s, 20/20 dual-stack overlay replies via relay %s\n' "$role" "$relay_id"
