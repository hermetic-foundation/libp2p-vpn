package org.hermeticfoundation.p2pvpn;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/** Available physical networks; preference changes do not revise surviving network leases. */
final class PhysicalNetworkInventory {
    static final int MAX_NETWORKS = 16;
    static final int MAX_ADDRESSES = 64;
    static final int MAX_ROUTES = 128;
    static final int MAX_BYTES = 131_072;

    static final class Route implements Comparable<Route> {
        final String destination;
        final int prefixLength;
        final String gateway;

        /** Null means the public API cannot reveal type, not that unicast was proven. */
        static Route candidate(String destination, int prefixLength, String gateway, Boolean unicast) {
            if (Boolean.FALSE.equals(unicast)) return null;
            // Prefixes only nominate Networks. A Network-bound kernel probe must
            // still establish usability, including when route type is unknown.
            return new Route(destination, prefixLength, gateway);
        }

        Route(String destination, int prefixLength, String gateway) {
            InetAddress address = numericAddress(destination);
            int bits = address.getAddress().length * 8;
            if (prefixLength < 0 || prefixLength > bits) {
                throw new IllegalArgumentException("Invalid physical route prefix");
            }
            byte[] network = address.getAddress();
            for (int bit = prefixLength; bit < bits; bit++) {
                network[bit / 8] &= ~(1 << (7 - bit % 8));
            }
            try {
                this.destination = InetAddress.getByAddress(network).getHostAddress();
            } catch (UnknownHostException impossible) {
                throw new IllegalArgumentException("Invalid physical route address", impossible);
            }
            this.prefixLength = prefixLength;
            InetAddress nextHop = gateway == null ? null : numericAddress(gateway);
            if (nextHop != null && nextHop.isAnyLocalAddress()) nextHop = null;
            if (nextHop != null && (nextHop.getAddress().length != network.length
                    || nextHop.isLoopbackAddress() || nextHop.isMulticastAddress())) {
                throw new IllegalArgumentException("Invalid physical route gateway");
            }
            this.gateway = nextHop == null ? null : nextHop.getHostAddress();
        }

        @Override
        public int compareTo(Route other) {
            int result = destination.compareTo(other.destination);
            if (result == 0) result = Integer.compare(prefixLength, other.prefixLength);
            if (result == 0) result = Objects.toString(gateway, "").compareTo(Objects.toString(other.gateway, ""));
            return result;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Route && compareTo((Route) other) == 0;
        }

        @Override
        public int hashCode() {
            return Objects.hash(destination, prefixLength, gateway);
        }

        JSONObject toJson() throws JSONException {
            JSONObject result = new JSONObject();
            result.put("destination", destination);
            result.put("prefix_length", prefixLength);
            result.put("gateway", gateway == null ? JSONObject.NULL : gateway);
            return result;
        }
    }

    static final class Data {
        final UnderlayTracker.Kind kind;
        final String interfaceName;
        final int interfaceIndex;
        final boolean validated;
        final List<String> addresses;
        final List<Route> routes;

        Data(UnderlayTracker.Kind kind, String interfaceName, int interfaceIndex,
                boolean validated, List<String> addresses, List<Route> routes) {
            if (kind == null || kind == UnderlayTracker.Kind.NONE || interfaceName == null
                    || interfaceName.isEmpty() || interfaceName.length() > 64
                    || interfaceName.chars().anyMatch(Character::isISOControl)
                    || interfaceIndex <= 0 || addresses == null || routes == null
                    || addresses.size() > MAX_ADDRESSES || routes.size() > MAX_ROUTES) {
                throw new IllegalArgumentException("Invalid physical network record");
            }
            TreeSet<String> canonical = new TreeSet<>();
            for (String value : addresses) {
                InetAddress address = numericAddress(value);
                if (address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isMulticastAddress()) {
                    throw new IllegalArgumentException("Invalid physical source address");
                }
                canonical.add(address.getHostAddress());
            }
            TreeSet<Route> ordered = new TreeSet<>();
            for (Route route : routes) ordered.add(Objects.requireNonNull(route));
            this.kind = kind;
            this.interfaceName = interfaceName;
            this.interfaceIndex = interfaceIndex;
            this.validated = validated;
            this.addresses = Collections.unmodifiableList(new ArrayList<>(canonical));
            this.routes = Collections.unmodifiableList(new ArrayList<>(ordered));
        }

        @Override
        public boolean equals(Object other) {
            if (!(other instanceof Data)) return false;
            Data value = (Data) other;
            return kind == value.kind && interfaceName.equals(value.interfaceName)
                    && interfaceIndex == value.interfaceIndex && validated == value.validated
                    && addresses.equals(value.addresses) && routes.equals(value.routes);
        }

        @Override
        public int hashCode() {
            return Objects.hash(kind, interfaceName, interfaceIndex, validated, addresses, routes);
        }
    }

    static final class Record {
        final long networkHandle;
        // Fences delayed callbacks independently of first complete publication.
        final long callbackToken;
        final long incarnation;
        final long revision;
        final Data data;

        Record(long networkHandle, long callbackToken, long incarnation, long revision, Data data) {
            this.networkHandle = networkHandle;
            this.callbackToken = callbackToken;
            this.incarnation = incarnation;
            this.revision = revision;
            this.data = data;
        }

        JSONObject toJson() throws JSONException {
            JSONObject value = new JSONObject();
            value.put("network_handle", networkHandle);
            value.put("incarnation", incarnation);
            value.put("revision", revision);
            value.put("kind", data.kind.label);
            value.put("interface_name", data.interfaceName);
            value.put("interface_index", data.interfaceIndex);
            value.put("validated", data.validated);
            value.put("addresses", new JSONArray(data.addresses));
            JSONArray routes = new JSONArray();
            for (Route route : data.routes) routes.put(route.toJson());
            value.put("routes", routes);
            return value;
        }
    }

    static final class Snapshot {
        final long revision;
        final Long preferredNetwork;
        final List<Record> networks;
        private final String json;

        Snapshot(long revision, Long preferredNetwork, List<Record> networks) {
            this.revision = revision;
            this.preferredNetwork = preferredNetwork;
            this.networks = Collections.unmodifiableList(new ArrayList<>(networks));
            try {
                JSONObject value = new JSONObject();
                value.put("revision", revision);
                value.put("preferred_network", preferredNetwork == null ? JSONObject.NULL : preferredNetwork);
                JSONArray records = new JSONArray();
                for (Record record : networks) records.put(record.toJson());
                value.put("networks", records);
                json = value.toString();
                if (json.getBytes(StandardCharsets.UTF_8).length > MAX_BYTES) {
                    throw new IllegalArgumentException("Physical inventory exceeds byte limit");
                }
            } catch (JSONException error) {
                throw new IllegalStateException("Cannot encode physical inventory", error);
            }
        }

        String toJson() { return json; }
    }

    private final AtomicLong revisions;
    private final AtomicLong incarnations;
    private final Map<Long, Record> available = new LinkedHashMap<>();
    private long revision;
    private Long preferred;
    private boolean withdrawn;

    PhysicalNetworkInventory() { this(new AtomicLong(), new AtomicLong()); }

    PhysicalNetworkInventory(AtomicLong revisions, AtomicLong incarnations) {
        this.revisions = revisions;
        this.incarnations = incarnations;
        revision = advance(revisions);
    }

    synchronized long available(long handle) {
        if (withdrawn) return 0;
        if (handle <= 0) throw new IllegalArgumentException("Invalid physical network handle");
        Record existing = available.get(handle);
        if (existing != null) return existing.callbackToken;
        if (available.size() == MAX_NETWORKS) return 0;
        long incarnation = advance(incarnations);
        revision = advance(revisions);
        available.put(handle, new Record(handle, incarnation, 0, revision, null));
        return incarnation;
    }

    synchronized boolean update(long handle, long incarnation, Data data) {
        Record existing = current(handle, incarnation);
        if (existing == null || Objects.equals(existing.data, Objects.requireNonNull(data))) return false;
        revision = advance(revisions);
        // An incomplete record may finish after newer networks have already published.
        long publishedIncarnation = existing.data == null ? advance(incarnations) : existing.incarnation;
        available.put(handle, new Record(handle, incarnation, publishedIncarnation, revision, data));
        try {
            snapshot();
        } catch (IllegalArgumentException error) {
            // Withdraw this record rather than retaining stale routing/source proof.
            available.put(handle, new Record(handle, incarnation, 0, revision, null));
            throw error;
        }
        return true;
    }

    synchronized boolean invalidate(long handle, long incarnation) {
        Record existing = current(handle, incarnation);
        if (existing == null || existing.data == null) return false;
        revision = advance(revisions);
        available.put(handle, new Record(handle, incarnation, 0, revision, null));
        return true;
    }

    synchronized boolean lost(long handle, long incarnation) {
        if (current(handle, incarnation) == null) return false;
        available.remove(handle);
        if (Objects.equals(preferred, handle)) preferred = null;
        revision = advance(revisions);
        return true;
    }

    synchronized boolean prefer(Long handle) {
        if (withdrawn) return false;
        if (handle != null && handle <= 0) throw new IllegalArgumentException("Invalid preferred network");
        if (Objects.equals(preferred, handle)) return false;
        preferred = handle;
        revision = advance(revisions);
        return true;
    }

    synchronized Snapshot withdraw() {
        if (!withdrawn) {
            revision = advance(revisions);
            available.clear();
            preferred = null;
            withdrawn = true;
        }
        return snapshot();
    }

    synchronized Snapshot snapshot() {
        List<Record> records = new ArrayList<>();
        Long publishedPreference = null;
        for (Record record : available.values()) {
            if (record.data != null) {
                records.add(record);
                if (Objects.equals(preferred, record.networkHandle)) publishedPreference = preferred;
            }
        }
        records.sort(Comparator.comparingLong(record -> record.incarnation));
        return new Snapshot(revision, publishedPreference, records);
    }

    private Record current(long handle, long incarnation) {
        Record record = available.get(handle);
        return record != null && record.callbackToken == incarnation ? record : null;
    }

    private static long advance(AtomicLong counter) {
        return counter.updateAndGet(value -> {
            if (value == Long.MAX_VALUE) throw new IllegalStateException("Physical inventory revision exhausted");
            return value + 1;
        });
    }

    private static InetAddress numericAddress(String value) {
        if (value == null || value.isEmpty() || value.length() > 45) {
            throw new IllegalArgumentException("Invalid numeric physical address");
        }
        boolean ipv6 = value.indexOf(':') >= 0;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (!(character >= '0' && character <= '9') && character != '.'
                    && !(ipv6 && (character == ':' || character >= 'a' && character <= 'f'
                            || character >= 'A' && character <= 'F'))) {
                throw new IllegalArgumentException("Physical address must be numeric and unscoped");
            }
        }
        try {
            if (!ipv6) {
                String[] octets = value.split("\\.", -1);
                if (octets.length != 4) throw new IllegalArgumentException("Physical IPv4 address must have four octets");
                byte[] bytes = new byte[4];
                for (int index = 0; index < 4; index++) {
                    if (octets[index].isEmpty() || octets[index].length() > 3) {
                        throw new IllegalArgumentException("Invalid physical IPv4 octet");
                    }
                    int octet = Integer.parseInt(octets[index]);
                    if (octet > 255) throw new IllegalArgumentException("Invalid physical IPv4 octet");
                    bytes[index] = (byte) octet;
                }
                return InetAddress.getByAddress(bytes);
            }
            return InetAddress.getByName(value);
        } catch (UnknownHostException error) {
            throw new IllegalArgumentException("Invalid numeric physical address", error);
        }
    }
}
