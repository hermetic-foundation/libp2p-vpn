package org.hermeticfoundation.p2pvpn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class UnderlayTrackerTest {
    private static UnderlayTracker selected(String id, UnderlayTracker.Kind kind) {
        UnderlayTracker tracker = new UnderlayTracker();
        tracker.observe(id, kind, true);
        assertEquals(UnderlayTracker.Change.INITIAL, tracker.selectDefault(id));
        return tracker;
    }

    @Test
    public void onlySelectedUnderlayTransitionsRequireRuntimeRecovery() {
        assertFalse(UnderlayTracker.Change.INITIAL.requiresRuntimeRecovery());
        assertFalse(UnderlayTracker.Change.UNCHANGED.requiresRuntimeRecovery());
        assertFalse(UnderlayTracker.Change.AVAILABLE_CHANGED.requiresRuntimeRecovery());
        assertTrue(UnderlayTracker.Change.CHANGED.requiresRuntimeRecovery());
        assertTrue(UnderlayTracker.Change.LOST.requiresRuntimeRecovery());
        assertTrue(UnderlayTracker.Change.RECOVERED.requiresRuntimeRecovery());
    }

    @Test
    public void availabilityDoesNotChooseANetwork() {
        UnderlayTracker tracker = new UnderlayTracker();
        assertEquals(UnderlayTracker.Change.AVAILABLE_CHANGED,
                tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true));
        tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true);
        tracker.observe("ethernet", UnderlayTracker.Kind.ETHERNET, true);
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(3, tracker.snapshot().availableNetworks);
        assertEquals(0, tracker.snapshot().selectionChanges);
    }

    @Test
    public void firstOsDefaultInitializesWithoutRecovery() {
        UnderlayTracker tracker = selected("cell", UnderlayTracker.Kind.CELLULAR);
        assertEquals("cellular", tracker.snapshot().kind);
        assertTrue(tracker.snapshot().validated);
        assertEquals(0, tracker.snapshot().selectionChanges);
        assertEquals(0, tracker.snapshot().recoveries);
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.selectDefault("cell"));
    }

    @Test
    public void defaultCanArriveBeforeInventory() {
        UnderlayTracker tracker = new UnderlayTracker();
        assertEquals(UnderlayTracker.Change.AVAILABLE_CHANGED, tracker.selectDefault("wifi"));
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.INITIAL,
                tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true));
        assertEquals("wifi", tracker.snapshot().kind);
    }

    @Test
    public void osCanPreferWifiOverEthernet() {
        UnderlayTracker tracker = selected("ethernet", UnderlayTracker.Kind.ETHERNET);
        assertEquals(UnderlayTracker.Change.AVAILABLE_CHANGED,
                tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true));
        assertEquals("ethernet", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.CHANGED, tracker.selectDefault("wifi"));
        assertEquals("wifi", tracker.snapshot().kind);
        assertEquals(1, tracker.snapshot().selectionChanges);
    }

    @Test
    public void osCanPreferCellularWhileWifiRemainsAvailable() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        tracker.selectDefault("cell");
        assertEquals("cellular", tracker.snapshot().kind);
        assertEquals(2, tracker.snapshot().availableNetworks);
    }

    @Test
    public void validationDoesNotOverrideOsChoice() {
        UnderlayTracker tracker = selected("cell", UnderlayTracker.Kind.CELLULAR);
        tracker.observe("wifi", UnderlayTracker.Kind.WIFI, false);
        tracker.selectDefault("wifi");
        assertEquals("wifi", tracker.snapshot().kind);
        assertFalse(tracker.snapshot().validated);
        assertEquals(UnderlayTracker.Change.CHANGED,
                tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true));
        assertTrue(tracker.snapshot().validated);
    }

    @Test
    public void losingSelectedNetworkWaitsForOsFallbackChoice() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        assertEquals(UnderlayTracker.Change.LOST, tracker.lost("wifi"));
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(1, tracker.snapshot().selectedLosses);
        assertEquals(UnderlayTracker.Change.RECOVERED, tracker.selectDefault("cell"));
        assertEquals("cellular", tracker.snapshot().kind);
        assertEquals(1, tracker.snapshot().recoveries);
    }

    @Test
    public void preferredReturnRequiresOsSelection() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        tracker.selectDefault("cell");
        tracker.lost("wifi");
        tracker.observe("wifi-return", UnderlayTracker.Kind.WIFI, true);
        assertEquals("cellular", tracker.snapshot().kind);
        tracker.selectDefault("wifi-return");
        assertEquals("wifi", tracker.snapshot().kind);
        assertEquals(2, tracker.snapshot().selectionChanges);
    }

    @Test
    public void lateLossOfOldDefaultDoesNotClearNewDefault() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        tracker.selectDefault("cell");
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.defaultLost("wifi"));
        assertEquals(UnderlayTracker.Change.AVAILABLE_CHANGED, tracker.lost("wifi"));
        assertEquals("cellular", tracker.snapshot().kind);
        assertEquals(0, tracker.snapshot().selectedLosses);
    }

    @Test
    public void bestMatchLossDoesNotWithdrawStillAvailableNetworks() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        assertEquals(UnderlayTracker.Change.LOST, tracker.defaultLost("wifi"));
        assertEquals(2, tracker.snapshot().availableNetworks);
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.RECOVERED, tracker.selectDefault("cell"));
        assertEquals(2, tracker.snapshot().availableNetworks);
        assertEquals("cellular", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.defaultLost("wifi"));
        assertEquals("cellular", tracker.snapshot().kind);
    }

    @Test
    public void defaultLossDoesNotSelectArbitraryAvailableNetwork() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.observe("cell", UnderlayTracker.Kind.CELLULAR, true);
        assertEquals(UnderlayTracker.Change.LOST, tracker.defaultLost("wifi"));
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(1, tracker.snapshot().selectedLosses);
        tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true);
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.RECOVERED, tracker.selectDefault("cell"));
    }

    @Test
    public void defaultAndPhysicalLossAreCountedOnce() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.defaultLost("wifi");
        tracker.lost("wifi");
        assertEquals(1, tracker.snapshot().selectedLosses);
        assertEquals(1, tracker.snapshot().selectionChanges);
    }

    @Test
    public void staleInventoryDoesNotRestoreLostDefault() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        tracker.lost("wifi");
        tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true);
        assertEquals("none", tracker.snapshot().kind);
        assertEquals(UnderlayTracker.Change.RECOVERED, tracker.selectDefault("wifi"));
    }

    @Test
    public void repeatedCallbacksDoNotChurnSelection() {
        UnderlayTracker tracker = selected("wifi", UnderlayTracker.Kind.WIFI);
        for (int i = 0; i < 100; i++) {
            assertEquals(UnderlayTracker.Change.UNCHANGED,
                    tracker.observe("wifi", UnderlayTracker.Kind.WIFI, true));
            assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.selectDefault("wifi"));
        }
        assertEquals(0, tracker.snapshot().selectionChanges);
    }

    @Test
    public void unknownCallbacksCannotChangeSelection() {
        UnderlayTracker tracker = new UnderlayTracker();
        assertEquals(UnderlayTracker.Change.UNCHANGED,
                tracker.observe(null, UnderlayTracker.Kind.WIFI, true));
        assertEquals(UnderlayTracker.Change.UNCHANGED,
                tracker.observe("", UnderlayTracker.Kind.WIFI, true));
        assertEquals(UnderlayTracker.Change.UNCHANGED,
                tracker.observe("invalid", UnderlayTracker.Kind.NONE, true));
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.selectDefault(""));
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.lost("missing"));
        assertEquals(UnderlayTracker.Change.UNCHANGED, tracker.defaultLost(null));
        assertEquals("none", tracker.snapshot().kind);
    }
}
