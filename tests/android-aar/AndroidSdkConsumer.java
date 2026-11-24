package example.consumer;

import org.hermeticfoundation.p2pvpn.NativeBridge;

final class AndroidSdkConsumer {
    void profile(String config, String artifacts, String stateDirectory) {
        NativeBridge.nativeCreateProfile("example", "phone");
        NativeBridge.nativeInspectProfile(config);
        NativeBridge.nativeRenameProfile(config, "other-phone");
        NativeBridge.nativeApplyPairingArtifacts(config, artifacts, stateDirectory);
    }

    void runtime(String request, int detachedTunFd, String inventory, String snapshot) {
        NativeBridge.nativeValidateStartNetworks(request);
        NativeBridge.nativeStartNetworks(request, detachedTunFd);
        NativeBridge.nativePhysicalNetworkInventoryChanged(inventory);
        NativeBridge.nativePhysicalNetworkChanged(snapshot);
        NativeBridge.nativeNetworkChanged();
        NativeBridge.nativeStatus();
        NativeBridge.nativeStop();
    }

    void membership(String networkId, String request, String memberPeer, String code) {
        NativeBridge.nativePairRpcForNetwork(networkId, request);
        NativeBridge.nativeJoinProfileByCode("join-1", code, "phone", "[]", "[]");
        NativeBridge.nativeCancelProfileJoin("join-1");
        NativeBridge.nativeRevokeMember(networkId, memberPeer);
        NativeBridge.nativeResignMembership(networkId);
    }
}
