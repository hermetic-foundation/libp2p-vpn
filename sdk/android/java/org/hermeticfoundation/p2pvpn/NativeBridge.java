package org.hermeticfoundation.p2pvpn;

/** JNI entry points for a host that owns its Android VPN service. */
public final class NativeBridge {
    static {
        System.loadLibrary("p2p_vpn_android");
    }

    private NativeBridge() {}

    public static native String nativeCreateProfile(String networkName, String hostname);

    static native String nativeCreateE2eProfile(
            String networkName,
            String bootstrapPeerId,
            String bootstrapAddress,
            String kademliaProtocol,
            String packetQuicListen,
            String packetQuicExternalEndpoint,
            String relayReservation,
            String additionalRoute);

    public static native String nativeInspectProfile(String configJson);

    public static native String nativeRenameProfile(String configJson, String hostname);

    static native String nativeStart(
            String networkId,
            String configJson,
            int tunFd,
            String pairingStatePath,
            String membershipStatePath);

    /**
     * Starts the requested overlays. Ownership of a valid detached TUN descriptor
     * transfers to the runtime even if it rejects the request.
     */
    public static native String nativeStartNetworks(String requestJson, int tunFd);

    public static native String nativeValidateStartNetworks(String requestJson);

    public static native String nativeStop();

    public static native String nativeStatus();

    static native String nativeDebugTransportSnapshot(String networkId);

    /** Requests recovery after the host has published the new physical network inventory. */
    public static native String nativeNetworkChanged();
    public static native String nativePhysicalNetworkChanged(String snapshot);
    public static native String nativePhysicalNetworkInventoryChanged(String inventory);

    static native String nativeDiagnosticDhtPause(String networkId, int seconds);
    static native String nativeDiagnosticProbePause(String networkId, int seconds);

    public static native String nativeRevokeMember(String networkId, String memberPeer);

    public static native String nativeResignMembership(String networkId);

    static native String nativePairRpc(String requestJson);

    public static native String nativePairRpcForNetwork(String networkId, String requestJson);

    public static native String nativeApplyPairingArtifacts(
            String configJson, String artifactsJson, String runtimeStateDirectory);

    public static native String nativeJoinProfileByCode(
            String operationId,
            String pairingCode,
            String hostname,
            String existingNetworkNamesJson,
            String candidateHintsJson);

    public static native String nativeCancelProfileJoin(String operationId);
}
