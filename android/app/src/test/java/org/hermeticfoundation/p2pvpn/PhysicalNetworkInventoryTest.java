package org.hermeticfoundation.p2pvpn;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.json.JSONObject;
import org.junit.Test;

public final class PhysicalNetworkInventoryTest {
    private static PhysicalNetworkInventory.Data data(String source) {
        return new PhysicalNetworkInventory.Data(UnderlayTracker.Kind.WIFI, "wlan0", 3, true,
                Collections.singletonList(source),
                Collections.singletonList(new PhysicalNetworkInventory.Route("0.0.0.0", 0, "192.0.2.254")));
    }

    private static PhysicalNetworkInventory.Data dnsData(List<String> servers) {
        PhysicalNetworkInventory.Data base = data("192.0.2.1");
        return new PhysicalNetworkInventory.Data(base.kind, base.interfaceName, base.interfaceIndex,
                base.validated, base.addresses, base.routes, servers);
    }

    private static long add(PhysicalNetworkInventory inventory, long handle, String source) {
        long token = inventory.available(handle);
        assertTrue(token > 0);
        assertTrue(inventory.update(handle, token, data(source)));
        return token;
    }

    private static PhysicalNetworkInventory.Record record(PhysicalNetworkInventory inventory, long handle) {
        return inventory.snapshot().networks.stream().filter(value -> value.networkHandle == handle)
                .findFirst().orElseThrow(() -> new AssertionError("Missing network " + handle));
    }

    @Test
    public void unknownRouteTypeRetainsDestinationSpecificCandidateMetadata() throws Exception {
        PhysicalNetworkInventory.Route lan = PhysicalNetworkInventory.Route.candidate(
                "192.168.42.99", 24, null, null);
        PhysicalNetworkInventory.Route ipv6 = PhysicalNetworkInventory.Route.candidate(
                "fd00:42::1234", 64, "::", null);
        PhysicalNetworkInventory.Route viaGateway = PhysicalNetworkInventory.Route.candidate(
                "10.20.99.1", 16, "192.168.42.1", null);
        PhysicalNetworkInventory.Route defaultRoute = PhysicalNetworkInventory.Route.candidate(
                "0.0.0.0", 0, "192.168.42.1", null);
        assertNotNull(lan);
        assertNotNull(ipv6);
        assertNotNull(viaGateway);
        assertNotNull(defaultRoute);
        assertEquals("192.168.42.0", lan.destination);
        assertEquals(24, lan.prefixLength);
        assertNull(lan.gateway);
        assertEquals(new PhysicalNetworkInventory.Route("fd00:42::", 64, null), ipv6);
        assertEquals(new PhysicalNetworkInventory.Route("10.20.0.0", 16, "192.168.42.1"), viaGateway);
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = inventory.available(10);
        inventory.update(10, token, new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 3, false,
                Collections.singletonList("192.168.42.2"),
                Arrays.asList(lan, ipv6, viaGateway, defaultRoute)));
        JSONObject network = new JSONObject(inventory.snapshot().toJson()).getJSONArray("networks").getJSONObject(0);
        assertEquals(4, network.getJSONArray("routes").length());
        assertFalse(network.getBoolean("validated"));
        assertTrue(inventory.snapshot().toJson().contains("192.168.42.0"));
        assertNull(inventory.snapshot().preferredNetwork);
        assertEquals(3, lan.toJson().length());
    }

    @Test
    public void knownNonUnicastRoutesAreRejectedRegardlessOfPrefix() {
        for (String destination : Arrays.asList("0.0.0.0", "192.168.42.0", "fd00:42::")) {
            int prefix = destination.equals("0.0.0.0") ? 0 : destination.indexOf(':') >= 0 ? 64 : 24;
            assertNull(PhysicalNetworkInventory.Route.candidate(destination, prefix, null, Boolean.FALSE));
            assertEquals(new PhysicalNetworkInventory.Route(destination, prefix, null),
                    PhysicalNetworkInventory.Route.candidate(destination, prefix, null, Boolean.TRUE));
        }
    }

    @Test
    public void unknownAndUnicastCandidatesKeepNumericFamilyAndPrefixValidation() {
        for (Boolean unicast : Arrays.asList(null, Boolean.TRUE)) {
            assertThrows(IllegalArgumentException.class, () -> PhysicalNetworkInventory.Route.candidate(
                    "router.example", 24, null, unicast));
            assertThrows(IllegalArgumentException.class, () -> PhysicalNetworkInventory.Route.candidate(
                    "192.168.42.0", 33, null, unicast));
            assertThrows(IllegalArgumentException.class, () -> PhysicalNetworkInventory.Route.candidate(
                    "fd00:42::", 129, null, unicast));
            assertThrows(IllegalArgumentException.class, () -> PhysicalNetworkInventory.Route.candidate(
                    "192.168.42.0", 24, "fe80::1", unicast));
            assertThrows(IllegalArgumentException.class, () -> PhysicalNetworkInventory.Route.candidate(
                    "fd00:42::", 64, "fe80::1%wlan0", unicast));
        }
    }

    @Test
    public void candidateAvailabilityAndLanRoutesDoNotSelectDefaultPreference() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        add(inventory, 10, "192.0.2.1");
        inventory.prefer(10L);
        PhysicalNetworkInventory.Record current = record(inventory, 10);
        long token = inventory.available(20);
        inventory.update(20, token, new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.ETHERNET, "eth0", 7, true,
                Collections.singletonList("192.168.42.2"),
                Collections.singletonList(PhysicalNetworkInventory.Route.candidate("192.168.42.0", 24, null, null))));
        assertEquals(Long.valueOf(10), inventory.snapshot().preferredNetwork);
        assertSame(current, record(inventory, 10));
        assertTrue(inventory.lost(20, token));
        assertEquals(Long.valueOf(10), inventory.snapshot().preferredNetwork);
        assertSame(current, record(inventory, 10));
    }

    @Test
    public void pendingDefaultClassificationClearsPreferenceWithoutRetiringCandidates() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        add(inventory, 10, "192.0.2.1");
        add(inventory, 20, "198.51.100.1");
        inventory.prefer(10L);
        PhysicalNetworkInventory.Record a = record(inventory, 10);
        PhysicalNetworkInventory.Record b = record(inventory, 20);
        // Default onAvailable clears preference until capabilities classify it.
        inventory.prefer(null);
        assertNull(inventory.snapshot().preferredNetwork);
        assertSame(a, record(inventory, 10));
        assertSame(b, record(inventory, 20));
        inventory.prefer(20L);
        assertEquals(Long.valueOf(20), inventory.snapshot().preferredNetwork);
        assertSame(a, record(inventory, 10));
        assertSame(b, record(inventory, 20));
        inventory.prefer(null);
        assertNull(inventory.snapshot().preferredNetwork);
        assertEquals(2, inventory.snapshot().networks.size());
    }

    @Test
    public void preferredReturnRetainsFallbackAndItsRevision() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        add(inventory, 10, "192.0.2.1");
        add(inventory, 20, "198.51.100.1");
        PhysicalNetworkInventory.Record a = record(inventory, 10);
        PhysicalNetworkInventory.Record b = record(inventory, 20);
        assertTrue(inventory.prefer(10L));
        long first = inventory.snapshot().revision;
        assertTrue(inventory.prefer(20L));
        assertTrue(inventory.snapshot().revision > first);
        assertEquals(Long.valueOf(20), inventory.snapshot().preferredNetwork);
        assertSame(a, record(inventory, 10));
        assertSame(b, record(inventory, 20));
        assertTrue(inventory.prefer(10L));
        assertEquals(Long.valueOf(10), inventory.snapshot().preferredNetwork);
        assertEquals(2, inventory.snapshot().networks.size());
        assertSame(a, record(inventory, 10));
        long revision = inventory.snapshot().revision;
        assertFalse(inventory.prefer(10L));
        assertEquals(revision, inventory.snapshot().revision);
    }

    @Test
    public void preferredNetworkMustHaveACompletePublishedRecord() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        inventory.prefer(10L);
        assertNull(inventory.snapshot().preferredNetwork);
        long token = inventory.available(10);
        assertTrue(inventory.snapshot().networks.isEmpty());
        assertNull(inventory.snapshot().preferredNetwork);
        inventory.update(10, token, data("192.0.2.1"));
        assertEquals(Long.valueOf(10), inventory.snapshot().preferredNetwork);
        inventory.invalidate(10, token);
        assertNull(inventory.snapshot().preferredNetwork);
    }

    @Test
    public void losingOldDefaultDoesNotClearCurrentPreference() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long a = add(inventory, 10, "192.0.2.1");
        add(inventory, 20, "198.51.100.1");
        inventory.prefer(10L);
        inventory.prefer(20L);
        assertTrue(inventory.lost(10, a));
        assertEquals(Long.valueOf(20), inventory.snapshot().preferredNetwork);
        assertEquals(1, inventory.snapshot().networks.size());
    }

    @Test
    public void reusedHandleGetsFreshIncarnationAndRejectsOldCallbacks() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long oldToken = add(inventory, 10, "192.0.2.1");
        long oldIncarnation = record(inventory, 10).incarnation;
        assertTrue(inventory.lost(10, oldToken));
        assertFalse(inventory.update(10, oldToken, data("192.0.2.2")));
        assertFalse(inventory.lost(10, oldToken));
        assertTrue(inventory.snapshot().networks.isEmpty());
        long newToken = add(inventory, 10, "192.0.2.3");
        assertTrue(newToken > oldToken);
        assertTrue(record(inventory, 10).incarnation > oldIncarnation);
        long revision = inventory.snapshot().revision;
        assertFalse(inventory.update(10, oldToken, data("192.0.2.4")));
        assertFalse(inventory.invalidate(10, oldToken));
        assertFalse(inventory.lost(10, oldToken));
        assertEquals(revision, inventory.snapshot().revision);
        assertEquals(Collections.singletonList("192.0.2.3"), record(inventory, 10).data.addresses);
    }

    @Test
    public void delayedCompletionCannotPublishAnIncarnationBelowTheHighWatermark() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long a = inventory.available(10);
        long b = inventory.available(20);
        inventory.update(20, b, data("198.51.100.1"));
        long watermark = record(inventory, 20).incarnation;
        inventory.update(10, a, data("192.0.2.1"));
        assertTrue(record(inventory, 10).incarnation > watermark);
        assertEquals(20, inventory.snapshot().networks.get(0).networkHandle);
        inventory.invalidate(20, b);
        long beforeReturn = record(inventory, 10).incarnation;
        inventory.update(20, b, data("198.51.100.2"));
        assertTrue(record(inventory, 20).incarnation > beforeReturn);
    }

    @Test
    public void serviceRecreationUsesProcessGlobalCounters() {
        AtomicLong revisions = new AtomicLong();
        AtomicLong incarnations = new AtomicLong();
        PhysicalNetworkInventory first = new PhysicalNetworkInventory(revisions, incarnations);
        add(first, 10, "192.0.2.1");
        PhysicalNetworkInventory.Snapshot old = first.snapshot();
        PhysicalNetworkInventory second = new PhysicalNetworkInventory(revisions, incarnations);
        assertTrue(second.snapshot().revision > old.revision);
        add(second, 10, "192.0.2.1");
        assertTrue(record(second, 10).incarnation > old.networks.get(0).incarnation);
    }

    @Test
    public void sourceRouteInterfaceAndCapabilityChangesAdvanceOnlyThatRecord() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long a = add(inventory, 10, "192.0.2.1");
        add(inventory, 20, "198.51.100.1");
        PhysicalNetworkInventory.Record b = record(inventory, 20);
        PhysicalNetworkInventory.Record initial = record(inventory, 10);
        long inventoryRevision = inventory.snapshot().revision;
        for (int index = 0; index < 100; index++) {
            assertFalse(inventory.update(10, a, data("192.0.2.1")));
        }
        assertSame(initial, record(inventory, 10));
        assertEquals(inventoryRevision, inventory.snapshot().revision);
        inventory.update(10, a, data("192.0.2.2"));
        assertTrue(record(inventory, 10).revision > initial.revision);
        assertEquals(initial.incarnation, record(inventory, 10).incarnation);
        long sourceRevision = record(inventory, 10).revision;
        PhysicalNetworkInventory.Data changed = new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 3, true,
                Collections.singletonList("192.0.2.2"),
                Collections.singletonList(new PhysicalNetworkInventory.Route("203.0.113.0", 24, null)));
        assertTrue(inventory.update(10, a, changed));
        assertTrue(record(inventory, 10).revision > sourceRevision);
        long routeRevision = record(inventory, 10).revision;
        PhysicalNetworkInventory.Data moved = new PhysicalNetworkInventory.Data(
                changed.kind, "wlan1", 9, changed.validated, changed.addresses, changed.routes);
        assertTrue(inventory.update(10, a, moved));
        assertTrue(record(inventory, 10).revision > routeRevision);
        long interfaceRevision = record(inventory, 10).revision;
        PhysicalNetworkInventory.Data unvalidated = new PhysicalNetworkInventory.Data(
                moved.kind, moved.interfaceName, moved.interfaceIndex, false, moved.addresses, moved.routes);
        assertTrue(inventory.update(10, a, unvalidated));
        assertTrue(record(inventory, 10).revision > interfaceRevision);
        long validationRevision = record(inventory, 10).revision;
        PhysicalNetworkInventory.Data cellular = new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.CELLULAR, unvalidated.interfaceName, unvalidated.interfaceIndex,
                unvalidated.validated, unvalidated.addresses, unvalidated.routes);
        assertTrue(inventory.update(10, a, cellular));
        assertTrue(record(inventory, 10).revision > validationRevision);
        long meaningfulRevision = inventory.snapshot().revision;
        assertFalse(inventory.update(10, a, new PhysicalNetworkInventory.Data(
                cellular.kind, cellular.interfaceName, cellular.interfaceIndex,
                cellular.validated, cellular.addresses, cellular.routes)));
        assertEquals(meaningfulRevision, inventory.snapshot().revision);
        assertEquals(initial.incarnation, record(inventory, 10).incarnation);
        assertSame(b, record(inventory, 20));
    }

    @Test
    public void snapshotsKeepTheirOwnContentAndRevision() throws Exception {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = add(inventory, 10, "192.0.2.1");
        PhysicalNetworkInventory.Snapshot queued = inventory.snapshot();
        inventory.update(10, token, data("192.0.2.2"));
        JSONObject old = new JSONObject(queued.toJson());
        assertEquals(queued.revision, old.getLong("revision"));
        JSONObject oldNetwork = old.getJSONArray("networks").getJSONObject(0);
        assertEquals(1, oldNetwork.getJSONArray("addresses").length());
        assertEquals("192.0.2.1", oldNetwork.getJSONArray("addresses").getString(0));
        JSONObject current = new JSONObject(inventory.snapshot().toJson());
        assertEquals("192.0.2.2", current.getJSONArray("networks").getJSONObject(0)
                .getJSONArray("addresses").getString(0));
        assertTrue(inventory.snapshot().revision > queued.revision);
        assertThrows(UnsupportedOperationException.class, queued.networks::clear);
    }

    @Test
    public void contractIsBoundedNumericAndUnscoped() throws Exception {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = inventory.available(10);
        inventory.update(10, token, new PhysicalNetworkInventory.Data(UnderlayTracker.Kind.ETHERNET,
                "eth0", 7, false, Arrays.asList("2001:db8::1", "192.0.2.1", "192.0.2.1"),
                Arrays.asList(new PhysicalNetworkInventory.Route("2001:db8::1234", 64, "fe80::1"),
                        new PhysicalNetworkInventory.Route("0.0.0.0", 0, "0.0.0.0"))));
        JSONObject json = new JSONObject(inventory.snapshot().toJson());
        assertEquals(3, json.length());
        assertTrue(json.getLong("revision") > 0);
        assertTrue(json.isNull("preferred_network"));
        JSONObject network = json.getJSONArray("networks").getJSONObject(0);
        assertEquals(11, network.length());
        assertEquals(10, network.getLong("network_handle"));
        assertTrue(network.getLong("incarnation") > 0);
        assertTrue(network.getLong("revision") > 0);
        assertEquals("ethernet", network.getString("kind"));
        assertEquals("eth0", network.getString("interface_name"));
        assertEquals(7, network.getInt("interface_index"));
        assertFalse(network.getBoolean("validated"));
        assertEquals(2, network.getJSONArray("addresses").length());
        assertEquals(0, network.getJSONArray("dns_servers").length());
        assertFalse(network.getBoolean("private_dns_active"));
        assertFalse(json.toString().contains("%"));
        assertTrue(network.getJSONArray("routes").getJSONObject(0).isNull("gateway"));
        assertEquals(3, network.getJSONArray("routes").getJSONObject(0).length());
    }

    @Test
    public void privateDnsDefaultsFalseForExistingConstructors() {
        PhysicalNetworkInventory.Data legacy = data("192.0.2.1");
        PhysicalNetworkInventory.Data withDns = dnsData(Collections.emptyList());
        PhysicalNetworkInventory.Data explicit = new PhysicalNetworkInventory.Data(legacy.kind,
                legacy.interfaceName, legacy.interfaceIndex, legacy.validated, legacy.addresses,
                legacy.routes, legacy.dnsServers, false);
        assertFalse(legacy.privateDnsActive);
        assertFalse(withDns.privateDnsActive);
        assertEquals(legacy, withDns);
        assertEquals(legacy, explicit);
        assertEquals(legacy.hashCode(), explicit.hashCode());
    }

    @Test
    public void privateDnsOnlyChangesPublishNewRevisions() throws Exception {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = add(inventory, 10, "192.0.2.1");
        PhysicalNetworkInventory.Record previous = record(inventory, 10);
        PhysicalNetworkInventory.Data base = previous.data;
        for (boolean active : new boolean[] {true, false}) {
            PhysicalNetworkInventory.Data value = new PhysicalNetworkInventory.Data(base.kind,
                    base.interfaceName, base.interfaceIndex, base.validated, base.addresses,
                    base.routes, base.dnsServers, active);
            assertNotEquals(previous.data, value);
            assertNotEquals(previous.data.hashCode(), value.hashCode());
            assertTrue(inventory.update(10, token, value));
            PhysicalNetworkInventory.Record current = record(inventory, 10);
            assertTrue(current.revision > previous.revision);
            assertTrue(inventory.snapshot().revision > previous.revision);
            assertEquals(previous.incarnation, current.incarnation);
            JSONObject network = new JSONObject(inventory.snapshot().toJson()).getJSONArray("networks").getJSONObject(0);
            assertEquals(active, network.getBoolean("private_dns_active"));
            PhysicalNetworkInventory.Data equivalent = new PhysicalNetworkInventory.Data(base.kind,
                    base.interfaceName, base.interfaceIndex, base.validated, base.addresses,
                    base.routes, base.dnsServers, active);
            assertEquals(value, equivalent);
            assertEquals(value.hashCode(), equivalent.hashCode());
            assertFalse(inventory.update(10, token, equivalent));
            assertEquals(current.revision, record(inventory, 10).revision);
            previous = current;
        }
    }

    @Test
    public void dnsServersPreserveOrderCanonicalizeAndCopyInput() throws Exception {
        List<String> servers = new ArrayList<>(Arrays.asList("198.51.100.53", "FE80::53", "192.0.2.53"));
        PhysicalNetworkInventory.Data value = dnsData(servers);
        servers.clear();
        assertEquals(Arrays.asList("198.51.100.53", "fe80:0:0:0:0:0:0:53", "192.0.2.53"), value.dnsServers);
        assertThrows(UnsupportedOperationException.class, () -> value.dnsServers.add("203.0.113.53"));
        PhysicalNetworkInventory.Data equivalent = dnsData(Arrays.asList(
                "198.51.100.53", "fe80:0:0:0:0:0:0:53", "192.0.2.53"));
        assertEquals(value, equivalent);
        assertEquals(value.hashCode(), equivalent.hashCode());
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        inventory.update(10, inventory.available(10), value);
        JSONObject network = new JSONObject(inventory.snapshot().toJson()).getJSONArray("networks").getJSONObject(0);
        assertEquals(3, network.getJSONArray("dns_servers").length());
        for (int index = 0; index < value.dnsServers.size(); index++) {
            assertEquals(value.dnsServers.get(index), network.getJSONArray("dns_servers").getString(index));
        }
        assertFalse(network.toString().contains("%"));
    }

    @Test
    public void dnsOnlyChangesAndReorderingPublishNewRevisions() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = add(inventory, 10, "192.0.2.1");
        PhysicalNetworkInventory.Record previous = record(inventory, 10);
        for (List<String> servers : Arrays.asList(
                Arrays.asList("198.51.100.53", "192.0.2.53"),
                Arrays.asList("192.0.2.53", "198.51.100.53"),
                Collections.singletonList("fe80::53"),
                Collections.<String>emptyList())) {
            PhysicalNetworkInventory.Data value = dnsData(servers);
            assertNotEquals(previous.data, value);
            assertTrue(inventory.update(10, token, value));
            PhysicalNetworkInventory.Record current = record(inventory, 10);
            assertTrue(current.revision > previous.revision);
            assertTrue(inventory.snapshot().revision > previous.revision);
            assertEquals(previous.incarnation, current.incarnation);
            assertFalse(inventory.update(10, token, dnsData(servers)));
            assertEquals(current.revision, record(inventory, 10).revision);
            previous = current;
        }
        assertEquals(data("192.0.2.1"), previous.data);
    }

    @Test
    public void dnsServerLimitRejectsOverflowWithoutTruncation() {
        List<String> servers = new ArrayList<>();
        for (int index = 1; index <= PhysicalNetworkInventory.MAX_DNS_SERVERS; index++) {
            servers.add("192.0.2." + index);
        }
        assertEquals(8, dnsData(servers).dnsServers.size());
        servers.add("192.0.2.9");
        assertThrows(IllegalArgumentException.class, () -> dnsData(servers));
    }

    @Test
    public void dnsServersRejectInvalidAddressesAndCanonicalDuplicates() {
        for (String server : Arrays.asList(null, "", "example.com", "192.0.2.999", "192.0.2.53:53",
                "0.0.0.0", "::", "127.0.0.1", "127.1.2.3", "::1", "224.0.0.53", "ff02::53",
                "::ffff:192.0.2.53", "::ffff:c000:235", "fe80::53%wlan0", "fe80::53%3")) {
            assertThrows(IllegalArgumentException.class, () -> dnsData(Collections.singletonList(server)));
        }
        assertThrows(IllegalArgumentException.class, () -> dnsData(null));
        assertThrows(IllegalArgumentException.class, () -> dnsData(Arrays.asList("192.0.2.53", "192.0.2.53")));
        assertThrows(IllegalArgumentException.class, () -> dnsData(Arrays.asList("fe80::53", "FE80:0:0:0:0:0:0:53")));
        assertTrue(dnsData(Collections.emptyList()).dnsServers.isEmpty());
    }

    @Test
    public void numericValidationRejectsHostnamesZonesAndInvalidRoutes() {
        for (String address : Arrays.asList("example.com", "192.0.2.", "192.0.2.999", "fe80::1%eth0", "::", "127.0.0.1", "ff02::1")) {
            assertThrows(IllegalArgumentException.class, () -> data(address));
        }
        assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Route("192.0.2.0", 33, null));
        assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Route("::", 129, null));
        for (String gateway : Arrays.asList("fe80::1", "127.0.0.1", "224.0.0.1")) {
            assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Route("0.0.0.0", 0, gateway));
        }
        assertNull(new PhysicalNetworkInventory.Route("::", 0, "::").gateway);
        assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 0, true, Collections.emptyList(), Collections.emptyList()));
    }

    @Test
    public void availableRecordsAndFieldCountsAreBoundedWithoutEvictingFallback() {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        for (int index = 1; index <= PhysicalNetworkInventory.MAX_NETWORKS; index++) add(inventory, index, "192.0.2.1");
        assertEquals(0, inventory.available(17));
        assertEquals(16, inventory.snapshot().networks.size());
        long token = inventory.available(1);
        assertTrue(inventory.lost(1, token));
        assertTrue(inventory.available(17) > 0);
        assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 3, true,
                Collections.nCopies(65, "192.0.2.1"), Collections.emptyList()));
        assertThrows(IllegalArgumentException.class, () -> new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 3, true, Collections.emptyList(),
                Collections.nCopies(129, new PhysicalNetworkInventory.Route("0.0.0.0", 0, null))));
    }

    @Test
    public void totalByteOverflowWithdrawsOnlyTheOversizedRecord() {
        List<String> addresses = new ArrayList<>();
        List<PhysicalNetworkInventory.Route> routes = new ArrayList<>();
        for (int index = 0; index < 64; index++) {
            addresses.add("fd00:1234:5678:abcd:1111:2222:3333:" + Integer.toHexString(index));
        }
        for (int index = 0; index < 128; index++) {
            routes.add(new PhysicalNetworkInventory.Route(
                    "2001:db8:1234:abcd:1111:2222:3333:" + Integer.toHexString(index), 128,
                    "fe80:1234:5678:abcd:1111:2222:3333:ffff"));
        }
        PhysicalNetworkInventory.Data large = new PhysicalNetworkInventory.Data(
                UnderlayTracker.Kind.WIFI, "wlan0", 3, true, addresses, routes);
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        boolean overflow = false;
        for (int index = 1; index <= 16; index++) {
            long token = inventory.available(index);
            int retained = inventory.snapshot().networks.size();
            try {
                inventory.update(index, token, large);
            } catch (IllegalArgumentException expected) {
                overflow = true;
                assertEquals(retained, inventory.snapshot().networks.size());
            }
            assertTrue(inventory.snapshot().toJson().getBytes(StandardCharsets.UTF_8).length <= 131_072);
        }
        assertTrue("Fixture must reach the total byte bound", overflow);
    }

    @Test
    public void teardownCapturesEmptyRevisionAndCannotResurrectOldCallbacks() throws Exception {
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory();
        long token = add(inventory, 10, "192.0.2.1");
        inventory.prefer(10L);
        long liveRevision = inventory.snapshot().revision;
        PhysicalNetworkInventory.Snapshot withdrawn = inventory.withdraw();
        assertTrue(withdrawn.revision > liveRevision);
        assertTrue(withdrawn.networks.isEmpty());
        assertNull(withdrawn.preferredNetwork);
        assertFalse(inventory.update(10, token, data("192.0.2.2")));
        assertEquals(0, inventory.available(10));
        assertFalse(inventory.prefer(10L));
        assertEquals(withdrawn.revision, inventory.withdraw().revision);
        JSONObject json = new JSONObject(withdrawn.toJson());
        assertEquals(withdrawn.revision, json.getLong("revision"));
        assertEquals(0, json.getJSONArray("networks").length());
        assertTrue(json.isNull("preferred_network"));
    }

    @Test
    public void delayedOldServiceWithdrawalNeverAcquiresANewRevision() {
        AtomicLong revisions = new AtomicLong();
        AtomicLong incarnations = new AtomicLong();
        PhysicalNetworkInventory old = new PhysicalNetworkInventory(revisions, incarnations);
        add(old, 10, "192.0.2.1");
        PhysicalNetworkInventory.Snapshot cleanup = old.withdraw();
        PhysicalNetworkInventory replacement = new PhysicalNetworkInventory(revisions, incarnations);
        add(replacement, 10, "192.0.2.2");
        long current = replacement.snapshot().revision;
        assertTrue(current > cleanup.revision);
        assertEquals(cleanup.revision, old.withdraw().revision);
        assertEquals(current, revisions.get());
        assertEquals(0, cleanup.networks.size());
        assertEquals(Collections.singletonList("192.0.2.2"), record(replacement, 10).data.addresses);
    }

    @Test
    public void countersFailClosedRatherThanWrapping() {
        assertThrows(IllegalStateException.class, () -> new PhysicalNetworkInventory(
                new AtomicLong(Long.MAX_VALUE), new AtomicLong()));
        PhysicalNetworkInventory inventory = new PhysicalNetworkInventory(new AtomicLong(), new AtomicLong(Long.MAX_VALUE));
        assertThrows(IllegalStateException.class, () -> inventory.available(10));
        assertTrue(inventory.snapshot().networks.isEmpty());
    }
}
