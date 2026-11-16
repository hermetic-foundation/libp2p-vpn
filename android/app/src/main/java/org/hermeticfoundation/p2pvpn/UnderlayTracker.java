package org.hermeticfoundation.p2pvpn;

import java.util.HashMap;
import java.util.Map;

final class UnderlayTracker {
    enum Change {
        INITIAL,
        UNCHANGED,
        AVAILABLE_CHANGED,
        CHANGED,
        LOST,
        RECOVERED;

        boolean requiresRuntimeRecovery() {
            return this == CHANGED || this == LOST || this == RECOVERED;
        }
    }

    enum Kind {
        NONE("none"),
        OTHER("other"),
        BLUETOOTH("bluetooth"),
        CELLULAR("cellular"),
        WIFI("wifi"),
        ETHERNET("ethernet");

        final String label;

        Kind(String label) {
            this.label = label;
        }
    }

    static final class Snapshot {
        final String kind;
        final boolean validated;
        final int availableNetworks;
        final long selectionChanges;
        final long selectedLosses;
        final long recoveries;

        private Snapshot(
                String kind,
                boolean validated,
                int availableNetworks,
                long selectionChanges,
                long selectedLosses,
                long recoveries) {
            this.kind = kind;
            this.validated = validated;
            this.availableNetworks = availableNetworks;
            this.selectionChanges = selectionChanges;
            this.selectedLosses = selectedLosses;
            this.recoveries = recoveries;
        }

        static Snapshot empty() {
            return new Snapshot(Kind.NONE.label, false, 0, 0, 0, 0);
        }
    }

    private static final class Candidate {
        final Kind kind;
        final boolean validated;

        Candidate(Kind kind, boolean validated) {
            this.kind = kind;
            this.validated = validated;
        }
    }

    private final Map<String, Candidate> availableNetworks = new HashMap<>();
    private String currentNetwork;
    private String defaultNetwork;
    private boolean initialized;
    private long selectionChanges;
    private long selectedLosses;
    private long recoveries;

    synchronized Change observe(String network, Kind kind, boolean validated) {
        if (network == null
                || network.isEmpty()
                || kind == null
                || kind == Kind.NONE) {
            return Change.UNCHANGED;
        }
        Candidate existing = availableNetworks.get(network);
        if (existing != null
                && existing.kind == kind
                && existing.validated == validated) {
            return Change.UNCHANGED;
        }
        boolean selectedCandidateChanged = network.equals(currentNetwork) && existing != null;
        availableNetworks.put(network, new Candidate(kind, validated));
        return reconcile(selectedCandidateChanged);
    }

    synchronized Change selectDefault(String network) {
        if (network != null && network.isEmpty()) {
            return Change.UNCHANGED;
        }
        if (java.util.Objects.equals(defaultNetwork, network)) {
            return Change.UNCHANGED;
        }
        defaultNetwork = network;
        return reconcile(false);
    }

    synchronized Change defaultLost(String network) {
        if (network == null || !network.equals(defaultNetwork)) {
            return Change.UNCHANGED;
        }
        if (network.equals(currentNetwork)) {
            selectedLosses = increment(selectedLosses);
        }
        defaultNetwork = null;
        return reconcile(false);
    }

    private Change reconcile(boolean selectedCandidateChanged) {
        String previous = currentNetwork;
        currentNetwork = availableNetworks.containsKey(defaultNetwork) ? defaultNetwork : null;
        if (java.util.Objects.equals(previous, currentNetwork)) {
            if (selectedCandidateChanged) {
                selectionChanges = increment(selectionChanges);
                return Change.CHANGED;
            }
            return Change.AVAILABLE_CHANGED;
        }
        if (currentNetwork == null) {
            selectionChanges = increment(selectionChanges);
            return Change.LOST;
        }
        if (previous == null) {
            if (!initialized) {
                initialized = true;
                return Change.INITIAL;
            }
            selectionChanges = increment(selectionChanges);
            recoveries = increment(recoveries);
            return Change.RECOVERED;
        }
        selectionChanges = increment(selectionChanges);
        return Change.CHANGED;
    }

    synchronized Change lost(String network) {
        if (network == null || !availableNetworks.containsKey(network)) {
            return Change.UNCHANGED;
        }
        boolean selected = network.equals(currentNetwork);
        availableNetworks.remove(network);
        if (network.equals(defaultNetwork)) {
            defaultNetwork = null;
        }
        if (!selected) {
            return Change.AVAILABLE_CHANGED;
        }
        selectedLosses = increment(selectedLosses);
        return reconcile(false);
    }

    synchronized Snapshot snapshot() {
        Candidate selected = availableNetworks.get(currentNetwork);
        if (selected == null) {
            return new Snapshot(
                    Kind.NONE.label,
                    false,
                    availableNetworks.size(),
                    selectionChanges,
                    selectedLosses,
                    recoveries);
        }
        return new Snapshot(
                selected.kind.label,
                selected.validated,
                availableNetworks.size(),
                selectionChanges,
                selectedLosses,
                recoveries);
    }

    private static long increment(long value) {
        return value == Long.MAX_VALUE ? value : value + 1;
    }
}
