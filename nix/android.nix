{
  pkgs,
  src ? ../.,
  version ? "0.1.0",
  androidSdkLicenseAccepted ? false,
  demandLifecycleTrial ? false,
}:

let
  inherit (pkgs) lib;

  pname = "p2p-vpn-android";
  arm64Abi = "arm64-v8a";
  x86_64Abi = "x86_64";
  abis = [
    arm64Abi
    x86_64Abi
  ];
  lifecycleTrialFeatures = lib.optional demandLifecycleTrial "demand-lifecycle-trial";
  minimumSdkVersion = "29";
  platformVersion = "37";
  buildToolsVersion = "37.0.0";
  ndkVersion = "28.2.13676358";

  androidNixpkgsConfig = {
    allowUnfree = true;
    android_sdk.accept_license = androidSdkLicenseAccepted;
  };

  # Keep Android's unfree toolchain policy local to this build module.
  androidPkgs = import pkgs.path {
    system = pkgs.stdenv.hostPlatform.system;
    config = androidNixpkgsConfig;
  };

  androidCrossSystem = lib.systems.examples.aarch64-android-prebuilt // {
    androidSdkVersion = minimumSdkVersion;
  };
  androidCrossPkgs = import pkgs.path {
    localSystem = pkgs.stdenv.hostPlatform.system;
    crossSystem = androidCrossSystem;
    config = androidNixpkgsConfig;
  };
  androidRustStd = androidCrossPkgs.buildPackages.rustc.unwrapped.overrideAttrs (previous: {
    preConfigure = (previous.preConfigure or "") + ''
      configureFlagsArray+=("--set=build.jobs=$NIX_BUILD_CORES")
    '';
  });
  androidRustc = androidCrossPkgs.buildPackages.rustc.override {
    rustc-unwrapped = androidRustStd;
    sysroot = androidRustStd;
  };
  androidRustPlatform = androidCrossPkgs.makeRustPlatform {
    cargo = pkgs.cargo;
    cargo-auditable = pkgs.cargo-auditable;
    rustc = androidRustc;
  };
  arm64RustTarget = androidCrossPkgs.stdenv.hostPlatform.rust.rustcTarget;
  x86_64RustTarget = "x86_64-linux-android";
  androidPageSizeRustFlags = lib.concatStringsSep " " [
    "-C link-arg=-Wl,-z,max-page-size=16384"
    "-C link-arg=-Wl,-z,common-page-size=16384"
  ];

  jdk = androidPkgs.jdk17;
  androidComposition = androidPkgs.androidenv.composeAndroidPackages {
    platformVersions = [ platformVersion ];
    buildToolsVersions = [ buildToolsVersion ];
    includeNDK = true;
    ndkVersions = [ ndkVersion ];
    includeCmake = false;
    includeEmulator = false;
    includeSources = false;
    includeSystemImages = false;
  };
  androidSdk = androidComposition.androidsdk;
  platformTools = androidComposition.platform-tools;
  androidHome = "${androidSdk}/libexec/android-sdk";
  androidNdkRoot = "${androidHome}/ndk/${ndkVersion}";

  androidBindings = src + "/sdk/android";
  rootManifest = src + "/Cargo.toml";
  rootLock = src + "/Cargo.lock";
  rootRustSource = src + "/src";
  vendorSource = src + "/vendor";
  browserManifest = src + "/crates/p2p-vpn-browser/Cargo.toml";
  browserRustSource = src + "/crates/p2p-vpn-browser/src";
  androidCrate = src + "/crates/p2p-vpn-android";
  androidE2eFixtureCrate = src + "/crates/p2p-vpn-android-e2e-fixture";
  nativeSourcesPresent = builtins.all builtins.pathExists [
    rootManifest
    rootLock
    rootRustSource
    vendorSource
    browserManifest
    browserRustSource
    androidCrate
    androidE2eFixtureCrate
  ];

  unavailable =
    name: reason:
    pkgs.runCommand name
      {
        passthru = {
          available = false;
          inherit reason;
        };
      }
      ''
        echo ${lib.escapeShellArg reason} >&2
        exit 1
      '';

  nativeSource = lib.fileset.toSource {
    root = src;
    fileset = lib.fileset.unions [
      rootManifest
      rootLock
      rootRustSource
      vendorSource
      browserManifest
      browserRustSource
      androidCrate
      androidE2eFixtureCrate
    ];
  };

  androidNativeArm64 =
    if nativeSourcesPresent then
      assert lib.assertMsg (
        androidCrossPkgs.stdenv.hostPlatform.androidSdkVersion == minimumSdkVersion
      ) "p2p-vpn Android Rust cross target must use API ${minimumSdkVersion}";
      assert lib.assertMsg (
        androidCrossPkgs.stdenv.hostPlatform.androidNdkVersion == "27"
      ) "p2p-vpn Android Rust cross target must retain the nixpkgs prebuilt NDK 27 toolchain";
      assert lib.assertMsg (androidCrossPkgs.stdenv.hostPlatform.useAndroidPrebuilt or false
      ) "p2p-vpn Android Rust cross target must retain the nixpkgs prebuilt Android toolchain";
      assert lib.assertMsg (lib.hasInfix "--keep-stage=0 --stage=1 build library" (
        androidRustc.unwrapped.buildPhase or ""
      )) "p2p-vpn Android Rust cross compiler must build only the target standard library";
      assert lib.assertMsg
        (lib.hasInfix "--sysroot ${builtins.unsafeDiscardStringContext (toString androidRustStd)}" androidRustc.buildCommand)
        "p2p-vpn Android compiler and sysroot must use the same bounded standard-library build";
      androidRustPlatform.buildRustPackage {
        pname = "${pname}-arm64";
        inherit version;
        src = nativeSource;
        cargoLock.lockFile = rootLock;
        buildFeatures = lifecycleTrialFeatures;
        cargoBuildFlags = [
          "--package"
          "p2p-vpn-android"
          "--lib"
        ];
        doCheck = false;
        strictDeps = true;
        RUSTFLAGS = androidPageSizeRustFlags;

        installPhase = ''
          runHook preInstall

          shared_library="target/${arm64RustTarget}/release/libp2p_vpn_android.so"
          if [[ ! -s "$shared_library" ]]; then
            echo "missing Android JNI library: $shared_library" >&2
            exit 1
          fi

          install -Dm755 \
            "$shared_library" \
            "$out/lib/${arm64Abi}/libp2p_vpn_android.so"

          runHook postInstall
        '';

        passthru = {
          available = true;
          abi = arm64Abi;
          rustTarget = arm64RustTarget;
          minimumSdk = lib.toInt minimumSdkVersion;
          toolchainNdkMajor = 27;
          rustCompiler = androidRustc;
        };
      }
    else
      unavailable "${pname}-native-source-missing" (
        "The Rust Android source is incomplete under ${toString src}; "
        + "Cargo.toml, Cargo.lock, src/, and crates/p2p-vpn-android/ are required."
      );

  # Nixpkgs only provides a prebuilt Rust standard library for Android arm64.
  # Build std for x86_64 with the pinned NDK.
  x86_64RustcSysroot = pkgs.symlinkJoin {
    name = "rustc-with-android-libsrc";
    paths = [ pkgs.rustc.unwrapped ];
    postBuild = ''
      mkdir -p "$out/lib/rustlib/src/rust"
      ln -s ${pkgs.rustPlatform.rustLibSrc} "$out/lib/rustlib/src/rust/library"
    '';
  };
  x86_64Rustc = pkgs.rustc.override { sysroot = x86_64RustcSysroot; };
  x86_64RustPlatform = pkgs.makeRustPlatform {
    cargo = pkgs.cargo;
    rustc = x86_64Rustc;
  };
  x86_64BaseCargoDeps = x86_64RustPlatform.importCargoLock { lockFile = rootLock; };
  x86_64CargoDeps = pkgs.symlinkJoin {
    # importCargoLock's config resolves this relative directory name.
    name = "cargo-vendor-dir";
    paths = [ x86_64BaseCargoDeps ];
    postBuild = ''
      for crate in ${pkgs.rustPlatform.rustLibSrc}/vendor/*; do
        name="$(basename "$crate")"
        if [[ ! -e "$out/$name" ]]; then
          ln -s "$crate" "$out/$name"
        fi
      done
    '';
  };
  x86_64Linker = "${androidNdkRoot}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android${minimumSdkVersion}-clang";

  androidNativeX86_64 =
    if nativeSourcesPresent then
      x86_64RustPlatform.buildRustPackage {
        pname = "${pname}-x86_64";
        inherit version;
        src = nativeSource;
        cargoDeps = x86_64CargoDeps;
        doCheck = false;
        strictDeps = true;
        auditable = false;

        env = {
          RUSTC_BOOTSTRAP = "1";
          CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = x86_64Linker;
          CC_x86_64_linux_android = x86_64Linker;
        };

        buildPhase = ''
          runHook preBuild

          cargo build \
            --jobs "$NIX_BUILD_CORES" \
            -Z build-std=std,panic_abort \
            --target ${x86_64RustTarget} \
            --offline \
            --release \
            --package p2p-vpn-android \
            --lib ${lib.optionalString demandLifecycleTrial "--features demand-lifecycle-trial"}

          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall

          shared_library="target/${x86_64RustTarget}/release/libp2p_vpn_android.so"
          if [[ ! -s "$shared_library" ]]; then
            echo "missing Android JNI library: $shared_library" >&2
            exit 1
          fi

          install -Dm755 \
            "$shared_library" \
            "$out/lib/${x86_64Abi}/libp2p_vpn_android.so"

          runHook postInstall
        '';

        passthru = {
          available = true;
          abi = x86_64Abi;
          rustTarget = x86_64RustTarget;
          minimumSdk = lib.toInt minimumSdkVersion;
          toolchainNdkMajor = 28;
        };
      }
    else
      unavailable "${pname}-x86_64-native-source-missing" (
        "The Rust Android source is incomplete under ${toString src}; "
        + "Cargo.toml, Cargo.lock, src/, and crates/p2p-vpn-android/ are required."
      );

  androidNative = pkgs.symlinkJoin {
    name = "${pname}-native-${version}";
    paths = [
      androidNativeArm64
      androidNativeX86_64
    ];
    passthru = {
      available = nativeSourcesPresent;
      inherit abis androidNativeArm64 androidNativeX86_64;
      minimumSdk = lib.toInt minimumSdkVersion;
    };
  };

  androidAar =
    if nativeSourcesPresent && builtins.pathExists (androidBindings + "/build-aar.sh") then
      pkgs.runCommand "libp2p-vpn-android-aar-${version}"
        {
          nativeBuildInputs = [ jdk ];
          passthru = {
            available = true;
            aarName = "libp2p-vpn-android.aar";
            inherit abis androidNative;
            minimumSdk = lib.toInt minimumSdkVersion;
          };
        }
        ''
          bash ${androidBindings}/build-aar.sh "$out/libp2p-vpn-android.aar" \
            "${androidNative}/lib" ${lib.escapeShellArgs abis}
        ''
    else
      unavailable "libp2p-vpn-android-aar-source-missing" (
        "The Android AAR needs the Rust JNI sources and sdk/android/ under ${toString src}."
      );

  androidRustTests =
    if nativeSourcesPresent then
      pkgs.rustPlatform.buildRustPackage {
        pname = "${pname}-rust-tests";
        inherit version;
        src = nativeSource;
        cargoLock.lockFile = rootLock;
        buildFeatures = lifecycleTrialFeatures;
        cargoBuildFlags = [
          "--package"
          "p2p-vpn-android"
          "--tests"
        ];
        cargoTestFlags = [
          "--package"
          "p2p-vpn-android"
        ];
        doCheck = true;
        strictDeps = true;

        installPhase = ''
          runHook preInstall
          touch "$out"
          runHook postInstall
        '';
      }
    else
      unavailable "${pname}-rust-tests-source-missing" (
        "The Rust Android source is incomplete under ${toString src}; "
        + "Cargo.toml, Cargo.lock, src/, and crates/p2p-vpn-android/ are required."
      );

  androidDevShell = androidPkgs.mkShellNoCC {
    packages = [
      androidSdk
      jdk
      platformTools
    ];

    ANDROID_HOME = androidHome;
    ANDROID_NDK_ROOT = androidNdkRoot;
    ANDROID_SDK_ROOT = androidHome;
    JAVA_HOME = jdk.home;
    LANG = "C.UTF-8";
    LC_ALL = "C.UTF-8";
  };

  androidCheck =
    pkgs.runCommand "${pname}-check"
      {
        nativeBuildInputs = [ pkgs.binutils ];
      }
      ''
        test -e ${androidRustTests}

        check_load_alignment() {
          local native="$1"
          local abi="$2"
          local alignment
          local load_segments=0

          while read -r alignment; do
            load_segments=$((load_segments + 1))
            if [[ ! "$alignment" =~ ^0x[0-9A-Fa-f]+$ ]] \
              || ((alignment < 0x4000))
            then
              echo "$abi JNI library has unsupported LOAD alignment: $alignment" >&2
              exit 1
            fi
          done < <(readelf -lW "$native" | awk '$1 == "LOAD" { print $NF }')

          if ((load_segments == 0)); then
            echo "$abi JNI library has no ELF LOAD segments" >&2
            exit 1
          fi
        }

        arm64_native=${androidNative}/lib/${arm64Abi}/libp2p_vpn_android.so
        if [[ ! -s "$arm64_native" ]]; then
          echo "missing Android JNI library: $arm64_native" >&2
          exit 1
        fi

        arm64_description="$(${pkgs.file}/bin/file -Lb "$arm64_native")"
        case "$arm64_description" in
          *"ARM aarch64"*"for Android ${minimumSdkVersion}"*"built by NDK r27"*) ;;
          *)
            echo "unexpected Android JNI ABI: $arm64_description" >&2
            exit 1
            ;;
        esac
        check_load_alignment "$arm64_native" ${lib.escapeShellArg arm64Abi}

        x86_64_native=${androidNative}/lib/${x86_64Abi}/libp2p_vpn_android.so
        if [[ ! -s "$x86_64_native" ]]; then
          echo "missing Android JNI library: $x86_64_native" >&2
          exit 1
        fi

        x86_64_description="$(${pkgs.file}/bin/file -Lb "$x86_64_native")"
        case "$x86_64_description" in
          *"x86-64"*"for Android ${minimumSdkVersion}"*"built by NDK r28"*) ;;
          *)
            echo "unexpected Android JNI ABI: $x86_64_description" >&2
            exit 1
            ;;
        esac
        check_load_alignment "$x86_64_native" ${lib.escapeShellArg x86_64Abi}

        mkdir -p "$out"
        printf '%s\n' "$arm64_description" "$x86_64_description" > "$out/native-abi.txt"
        printf '%s\n' native-only > "$out/scope.txt"
      '';
in
{
  inherit
    androidAar
    androidCheck
    androidDevShell
    androidNative
    androidNativeArm64
    androidNativeX86_64
    androidRustTests
    androidSdk
    ;

  androidBuildConfig = {
    abi = arm64Abi;
    rustTarget = arm64RustTarget;
    inherit
      abis
      buildToolsVersion
      ndkVersion
      platformVersion
      ;
    rustTargets = {
      arm64 = arm64RustTarget;
      x86_64 = x86_64RustTarget;
    };
    minimumSdk = lib.toInt minimumSdkVersion;
    inherit nativeSourcesPresent demandLifecycleTrial;
    jdkVersion = lib.versions.major jdk.version;
    rustToolchainNdkMajor = lib.toInt androidCrossPkgs.stdenv.hostPlatform.androidNdkVersion;
    rustUsesAndroidPrebuilt = androidCrossPkgs.stdenv.hostPlatform.useAndroidPrebuilt or false;
  };
}
