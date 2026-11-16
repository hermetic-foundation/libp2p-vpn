package org.hermeticfoundation.p2pvpn;

import static org.junit.Assert.*;

import android.net.ConnectivityManager;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public final class ServiceNetworkCallbackTest {
    @Test
    public void retirementClearsCallbackOwnershipAndClosesTheWorkerScopeOnce() throws Exception {
        ServiceRuntimeWorker.Dispatcher dispatcher = new ServiceRuntimeWorker.Dispatcher();
        AtomicInteger cleanups = new AtomicInteger();
        ServiceRuntimeWorker.Scope scope = dispatcher.open(cleanups::incrementAndGet);
        try {
            P2pVpnService service = new P2pVpnService();
            set(service, "worker", scope);
            set(service, "physicalCallbackOwner", new Object());
            set(service, "networkCallback", new ConnectivityManager.NetworkCallback());
            set(service, "defaultNetworkCallback", new ConnectivityManager.NetworkCallback());
            PhysicalNetworkInventory inventory = (PhysicalNetworkInventory) get(service, "physicalInventory");
            long token = inventory.available(10);
            inventory.update(10, token, new PhysicalNetworkInventory.Data(
                    UnderlayTracker.Kind.WIFI, "wlan0", 3, true,
                    java.util.Collections.singletonList("192.0.2.1"), java.util.Collections.emptyList()));
            long liveRevision = inventory.snapshot().revision;
            ScheduledFuture<?> pending = scope.schedule(() -> fail("retired work ran"), 1, TimeUnit.DAYS);
            Method retire = P2pVpnService.class.getDeclaredMethod("retireServiceScope");
            retire.setAccessible(true);
            retire.invoke(service);
            assertNull(get(service, "physicalCallbackOwner"));
            assertNull(get(service, "connectivityManager"));
            assertNull(get(service, "networkCallback"));
            assertNull(get(service, "defaultNetworkCallback"));
            assertTrue(scope.isClosed());
            assertTrue(pending.isCancelled());
            assertEquals(0, scope.pendingTaskCount());
            scope.cleanupCompletion().get(2, TimeUnit.SECONDS);
            assertEquals(1, cleanups.get());
            PhysicalNetworkInventory.Snapshot withdrawn =
                    (PhysicalNetworkInventory.Snapshot) get(service, "withdrawnPhysicalInventory");
            assertTrue(withdrawn.revision > liveRevision);
            assertTrue(withdrawn.networks.isEmpty());
            assertSame(withdrawn, get(service, "latestPhysicalInventory"));
            retire.invoke(service);
            assertSame(withdrawn, get(service, "withdrawnPhysicalInventory"));
            assertEquals(withdrawn.revision, inventory.snapshot().revision);
            assertEquals(1, cleanups.get());
        } finally {
            dispatcher.close();
            assertTrue(dispatcher.awaitTermination(2, TimeUnit.SECONDS));
        }
    }

    private static void set(P2pVpnService service, String name, Object value) throws Exception {
        Field field = P2pVpnService.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(service, value);
    }

    private static Object get(P2pVpnService service, String name) throws Exception {
        Field field = P2pVpnService.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(service);
    }
}
