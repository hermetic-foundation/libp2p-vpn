package org.hermeticfoundation.p2pvpn;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Test;

public final class DebugTransportSnapshotWorkerTest {
    @Test
    public void admitsOneReadRejectsQueueAndLetsAdmittedReadFinishOnClose() throws Exception {
        DebugTransportSnapshotWorker worker = new DebugTransportSnapshotWorker();
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicBoolean finished = new AtomicBoolean();
        try {
            assertTrue(worker.tryExecute(() -> {
                started.countDown();
                try {
                    release.await();
                    finished.set(true);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                }
            }));
            assertTrue(started.await(2, TimeUnit.SECONDS));
            assertFalse(worker.tryExecute(() -> {
                throw new AssertionError("requests must not queue");
            }));
            worker.close();
            assertFalse(worker.tryExecute(() -> {}));
            assertFalse(worker.awaitTermination(10, TimeUnit.MILLISECONDS));
        } finally {
            release.countDown();
            worker.close();
        }
        assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS));
        assertTrue(finished.get());
    }
}
