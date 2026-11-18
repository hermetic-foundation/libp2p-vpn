package org.hermeticfoundation.p2pvpn;

import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** One on-demand native read, no queued requests and no idle worker retention. */
final class DebugTransportSnapshotWorker implements AutoCloseable {
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            0, 1, 15, TimeUnit.SECONDS, new SynchronousQueue<>(), runnable -> {
                Thread thread = new Thread(runnable, "p2p-vpn-debug-transport");
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());

    boolean tryExecute(Runnable action) {
        Objects.requireNonNull(action);
        try {
            executor.execute(action);
            return true;
        } catch (RejectedExecutionException busy) {
            return false;
        }
    }

    @Override
    public void close() {
        executor.shutdown();
    }

    boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return executor.awaitTermination(timeout, unit);
    }
}
