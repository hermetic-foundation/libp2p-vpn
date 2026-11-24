#![cfg(windows)]

use p2p_vpn::{private_fs, runtime::pairing_store::PairingStateStore};
use std::{
    fs,
    io::Write as _,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
#[ignore = "requires elevation for durable Windows volume flushes"]
fn private_state_roundtrip_and_access_checks() {
    let directory = std::env::temp_dir().join(format!(
        "p2p-vpn-windows-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    private_fs::ensure_private_directory(&directory).unwrap();
    let path = directory.join("pairing.json");
    let store =
        PairingStateStore::encrypted(&path, "test-identity", "test-network", "test-peer").unwrap();
    store.save(b"first state").unwrap();
    assert_eq!(store.load().unwrap().unwrap(), b"first state");
    store.save(b"replacement state").unwrap();
    assert_eq!(store.load().unwrap().unwrap(), b"replacement state");
    let durable_ciphertext = fs::read(&path).unwrap();
    store.save(b"replacement state").unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        durable_ciphertext,
        "unchanged durable state must retain its authenticated ciphertext"
    );
    fs::write(&path, b"external corruption").unwrap();
    store.save(b"replacement state").unwrap();
    assert_eq!(store.load().unwrap().unwrap(), b"replacement state");
    assert!(
        !fs::read(&path)
            .unwrap()
            .windows(17)
            .any(|b| b == b"replacement state")
    );
    private_fs::validate_private(&path).unwrap();
    let wrong_key =
        PairingStateStore::encrypted(&path, "wrong-identity", "test-network", "test-peer").unwrap();
    assert!(wrong_key.load().is_err());
    let mut private = private_fs::create_private_file(&directory.join("secret.key")).unwrap();
    private.write_all(b"private secret").unwrap();
    drop(private);
    assert_eq!(
        private_fs::create_private_file(&path).unwrap_err().kind(),
        std::io::ErrorKind::AlreadyExists
    );
    // A normal inherited file lacks an explicitly protected DACL and is rejected.
    let inherited = directory.join("inherited.json");
    fs::write(&inherited, b"{}").unwrap();
    assert!(private_fs::validate_private(&inherited).is_err());
    store.remove().unwrap();
    assert!(store.load().unwrap().is_none());
    fs::remove_dir_all(directory).unwrap();
}
