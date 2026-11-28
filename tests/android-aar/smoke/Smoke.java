package example.aarsmoke;

import android.app.Activity;
import android.app.Instrumentation;
import android.os.Bundle;
import org.hermeticfoundation.p2pvpn.NativeBridge;
import org.json.JSONObject;

public final class Smoke extends Instrumentation {
    private static final String NETWORK = "aar-smoke";
    private static final String ORIGINAL = "before-rename";
    private static final String RENAMED = "after-rename";

    @Override
    public void onCreate(Bundle args) {
        super.onCreate(args);
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        try {
            String phase = value("status", NativeBridge.nativeStatus()).getString("phase");
            require("stopped".equals(phase), "cold status is " + phase);

            JSONObject created = value("create", NativeBridge.nativeCreateProfile(NETWORK, ORIGINAL));
            String peer = created.getString("peer_id");
            require(!peer.isEmpty(), "create returned an empty peer ID");
            checkProfile("create", created, ORIGINAL, peer);

            String config = created.getString("config_json");
            checkProfile("inspect", value("inspect", NativeBridge.nativeInspectProfile(config)), ORIGINAL, peer);
            JSONObject renamed = value("rename", NativeBridge.nativeRenameProfile(config, RENAMED));
            checkProfile("rename", renamed, RENAMED, peer);
            JSONObject reopened = value("reinspect",
                    NativeBridge.nativeInspectProfile(renamed.getString("config_json")));
            checkProfile("reinspect", reopened, RENAMED, peer);

            result.putString("stream", "\nPASS Android AAR preserves peer identity across rename\n");
            finish(Activity.RESULT_OK, result);
        } catch (Exception | AssertionError | LinkageError failure) {
            result.putString("stream", "\nFAIL " + failure + "\n");
            finish(Activity.RESULT_CANCELED, result);
        }
    }

    private static JSONObject value(String operation, String json) throws Exception {
        JSONObject envelope = new JSONObject(json);
        require(envelope.getBoolean("ok"), operation + " returned " + envelope.optString("error"));
        return envelope.getJSONObject("value");
    }

    private static void checkProfile(String operation, JSONObject profile, String hostname, String peer)
            throws Exception {
        require(NETWORK.equals(profile.getString("network_name")), operation + " changed the network");
        require(hostname.equals(profile.getString("hostname")), operation + " returned the wrong hostname");
        require(peer.equals(profile.getString("peer_id")), operation + " changed the peer ID");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
