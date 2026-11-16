package org.hermeticfoundation.p2pvpn;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import org.json.JSONObject;
import org.junit.Test;

public final class PhysicalNetworkSnapshotTest {
    @Test
    public void disconnectedSnapshotIsExplicitAndEmpty() throws Exception {
        JSONObject value = new JSONObject(PhysicalNetworkSnapshot.none(0).toJson());
        assertEquals("none", value.getString("kind"));
        assertTrue(value.isNull("interface_name"));
        assertTrue(value.isNull("network_handle"));
        assertEquals(0, value.getJSONArray("addresses").length());
    }

    @Test
    public void addressesAreCanonicalAndImmutable() throws Exception {
        ArrayList<String> source = new ArrayList<>(Arrays.asList("fe80::1", "100.64.1.2", "100.64.1.2"));
        PhysicalNetworkSnapshot value = new PhysicalNetworkSnapshot(7, UnderlayTracker.Kind.WIFI, "wlan0", 123L, source);
        source.clear();
        assertEquals(Arrays.asList("100.64.1.2", "fe80::1"), value.addresses);
        JSONObject json = new JSONObject(value.toJson());
        assertEquals(7, json.getLong("generation"));
        assertEquals(123, json.getLong("network_handle"));
        assertEquals("wifi", json.getString("kind"));
        assertEquals("wlan0", json.getString("interface_name"));
        try {
            value.addresses.clear();
            fail("Mutable snapshot");
        } catch (UnsupportedOperationException expected) {
            // Snapshot ownership does not depend on the caller retaining its input.
        }
    }

    @Test
    public void equivalentCallbackOrderDoesNotRequireAnotherGeneration() {
        PhysicalNetworkSnapshot a = new PhysicalNetworkSnapshot(1, UnderlayTracker.Kind.WIFI, "wlan0", 1L,
                Arrays.asList("192.0.2.1", "2001:db8::1"));
        PhysicalNetworkSnapshot b = new PhysicalNetworkSnapshot(2, UnderlayTracker.Kind.WIFI, "wlan0", 1L,
                Arrays.asList("2001:db8::1", "192.0.2.1"));
        assertTrue(a.sameSelection(b));
        assertFalse(a.sameSelection(new PhysicalNetworkSnapshot(3, UnderlayTracker.Kind.WIFI, "wlan0", 2L, b.addresses)));
        assertFalse(a.sameSelection(new PhysicalNetworkSnapshot(3, UnderlayTracker.Kind.WIFI, "wlan0", 1L,
                Collections.singletonList("192.0.2.2"))));
        assertFalse(a.sameSelection(new PhysicalNetworkSnapshot(3, UnderlayTracker.Kind.CELLULAR, "rmnet1", 1L, b.addresses)));
    }

    @Test(expected = IllegalArgumentException.class)
    public void disconnectedSnapshotCannotCarryAddresses() {
        new PhysicalNetworkSnapshot(1, UnderlayTracker.Kind.NONE, null, null, Collections.singletonList("192.0.2.1"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void snapshotsAreAddressBounded() {
        new PhysicalNetworkSnapshot(1, UnderlayTracker.Kind.WIFI, "wlan0", 1L, Collections.nCopies(65, "192.0.2.1"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void interfaceNamesCannotContainControlCharacters() {
        new PhysicalNetworkSnapshot(1, UnderlayTracker.Kind.WIFI, "wlan0\0", 1L, Collections.emptyList());
    }
}
