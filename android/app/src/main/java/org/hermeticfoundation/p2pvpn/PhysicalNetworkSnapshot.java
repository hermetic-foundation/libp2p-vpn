package org.hermeticfoundation.p2pvpn;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

final class PhysicalNetworkSnapshot {
    final long generation;
    final UnderlayTracker.Kind kind;
    final String interfaceName;
    final Long networkHandle;
    final List<String> addresses;

    PhysicalNetworkSnapshot(long generation, UnderlayTracker.Kind kind, String interfaceName,
            Long networkHandle, List<String> addresses) {
        if (generation < 0 || kind == null || addresses == null || addresses.size() > 64) {
            throw new IllegalArgumentException("Invalid physical network snapshot");
        }
        if (kind == UnderlayTracker.Kind.NONE) {
            if (interfaceName != null || networkHandle != null || !addresses.isEmpty()) {
                throw new IllegalArgumentException("Disconnected snapshot contains interface data");
            }
        } else if (interfaceName == null || interfaceName.isEmpty() || interfaceName.length() > 64
                || interfaceName.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Invalid physical interface name");
        }
        this.generation = generation;
        this.kind = kind;
        this.interfaceName = interfaceName;
        this.networkHandle = networkHandle;
        this.addresses = Collections.unmodifiableList(new java.util.ArrayList<>(new TreeSet<>(addresses)));
    }

    static PhysicalNetworkSnapshot none(long generation) {
        return new PhysicalNetworkSnapshot(generation, UnderlayTracker.Kind.NONE, null, null, Collections.emptyList());
    }

    boolean sameSelection(PhysicalNetworkSnapshot other) {
        return kind == other.kind && Objects.equals(interfaceName, other.interfaceName)
                && Objects.equals(networkHandle, other.networkHandle) && addresses.equals(other.addresses);
    }

    String toJson() {
        try {
            JSONObject result = new JSONObject();
            result.put("generation", generation);
            result.put("kind", kind.label);
            result.put("interface_name", interfaceName == null ? JSONObject.NULL : interfaceName);
            result.put("network_handle", networkHandle == null ? JSONObject.NULL : networkHandle);
            result.put("addresses", new JSONArray(addresses));
            return result.toString();
        } catch (JSONException error) {
            throw new IllegalStateException("Cannot encode physical network snapshot", error);
        }
    }
}
