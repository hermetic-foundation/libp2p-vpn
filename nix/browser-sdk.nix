{
  pkgs,
  src,
  cargoLock,
}:
let
  version = "0.2.126";
  bindgen = pkgs.fetchurl {
    url = "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}/wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz";
    hash = "sha256-BklI1Y4tbAp0UhZHemObppYhbWMJqqkCk50bhlsdhp0=";
  };
in
pkgs.rustPlatform.buildRustPackage {
  pname = "libp2p-vpn-browser-sdk";
  version = "0.1.0";
  inherit src cargoLock;

  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_LINKER = "${pkgs.llvmPackages.lld}/bin/wasm-ld";
  CARGO_PROFILE_DEV_DEBUG = "0";

  nativeBuildInputs = [ pkgs.jq ];
  buildPhase = ''
    runHook preBuild
    mkdir -p "$TMPDIR/bindgen"
    tar xf ${bindgen} -C "$TMPDIR/bindgen" --strip-components=1
    export PATH="$TMPDIR/bindgen:$PATH"
    bash scripts/build-browser-sdk.sh "$TMPDIR/browser-sdk"
    runHook postBuild
  '';
  doCheck = false;
  installPhase = ''
    runHook preInstall
    cp -r "$TMPDIR/browser-sdk" "$out"
    runHook postInstall
  '';
}
