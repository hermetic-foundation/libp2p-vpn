{
  description = "Rust foundation for a libp2p-native packet-oriented mesh VPN";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
    in
    flake-utils.lib.eachSystem supportedSystems (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = nixpkgs.lib;
        androidSupported = system == "x86_64-linux";
        android =
          if androidSupported then
            import ./nix/android.nix {
              inherit pkgs;
              androidSdkLicenseAccepted = true;
            }
          else
            null;
        androidLifecycleTrial =
          if androidSupported then
            import ./nix/android.nix {
              inherit pkgs;
              androidSdkLicenseAccepted = true;
              demandLifecycleTrial = true;
            }
          else
            null;
        rust = pkgs.rustc;
        cargo = pkgs.cargo;
        rustSource = lib.fileset.toSource {
          root = ./.;
          fileset = lib.fileset.unions [
            ./Cargo.toml
            ./Cargo.lock
            ./vendor
            ./crates/p2p-vpn-android
            ./crates/p2p-vpn-android-e2e-fixture
            ./crates/p2p-vpn-browser/Cargo.toml
            ./crates/p2p-vpn-browser/examples
            ./crates/p2p-vpn-browser/src
            ./docs/developer/protocol/vectors.json
            ./examples/native_embedding.rs
            ./src
            (lib.fileset.fileFilter (file: file.hasExt "rs") ./tests)
          ];
        };
        package = pkgs.rustPlatform.buildRustPackage {
          pname = "libp2p-vpn";
          version = "0.1.0";
          src = rustSource;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "--lib" ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          RUST_MIN_STACK = "8388608";
          installPhase = ''
            runHook preInstall
            install -Dm644 target/${pkgs.stdenv.targetPlatform.rust.cargoShortTarget}/"$cargoBuildType"/libp2p_vpn.rlib \
              "$out/lib/libp2p_vpn.rlib"
            runHook postInstall
          '';
        };
        androidE2eFixture = pkgs.rustPlatform.buildRustPackage {
          pname = "p2p-vpn-android-e2e-fixture";
          version = "0.1.0";
          src = rustSource;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "p2p-vpn-android-e2e-fixture"
          ];
          cargoTestFlags = [
            "--package"
            "p2p-vpn-android-e2e-fixture"
          ];
          nativeBuildInputs = [ pkgs.pkg-config ];
          RUST_MIN_STACK = "8388608";
        };
        checkFast = pkgs.writeShellApplication {
          name = "p2p-vpn-check-fast";
          runtimeInputs = [
            cargo
            rust
            pkgs.clippy
            pkgs.rustfmt
            pkgs.pkg-config
            pkgs.stdenv.cc
          ];
          text = ''
            if [[ ! -f Cargo.toml || ! -d src ]]; then
              echo "p2p-vpn-check-fast must be run from the libp2p-vpn repository root" >&2
              exit 2
            fi

            export RUST_BACKTRACE="''${RUST_BACKTRACE:-1}"
            export RUST_MIN_STACK="''${RUST_MIN_STACK:-8388608}"
            cargo fmt -- --check
            cargo test
            cargo clippy --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
          '';
        };
        isolatedTestRunner = pkgs.writeShellScript "p2p-vpn-isolated-test-runner" ''
          set -euo pipefail
          ip link set lo up
          exec cargo test --offline --locked "$@"
        '';
        checkIsolated = pkgs.writeShellScriptBin "p2p-vpn-check-isolated" ''
          set -euo pipefail
          export PATH=${
            lib.makeBinPath [
              cargo
              rust
              pkgs.iproute2
              pkgs.pkg-config
              pkgs.stdenv.cc
              pkgs.util-linux
            ]
          }:"$PATH"
          if [[ ! -f Cargo.toml || ! -d src ]]; then
            echo "p2p-vpn-check-isolated must be run from the libp2p-vpn repository root" >&2
            exit 2
          fi
          export CARGO_BUILD_JOBS="''${CARGO_BUILD_JOBS:-2}"
          if [[ -z "''${CARGO_TARGET_DIR:-}" ]]; then
              export CARGO_TARGET_DIR="''${XDG_CACHE_HOME:-$HOME/.cache}/libp2p-vpn/target"
          fi
          export CARGO_INCREMENTAL=0
          export CARGO_PROFILE_DEV_DEBUG=0
          export CARGO_PROFILE_TEST_DEBUG=0
          export RUST_BACKTRACE="''${RUST_BACKTRACE:-1}"
          export RUST_MIN_STACK="''${RUST_MIN_STACK:-8388608}"
          if [[ "$#" -eq 0 ]]; then
            set -- --workspace --all-targets
          fi
          exec unshare --user --map-root-user --mount --net --pid --fork \
            --kill-child=SIGKILL --mount-proc -- ${isolatedTestRunner} "$@"
        '';
        androidBatteryPython = pkgs.python3.withPackages (ps: [ ps.protobuf ]);
        androidBatterySources = lib.fileset.toSource {
          root = ./scripts;
          fileset = lib.fileset.unions [
            ./scripts/android-battery-decode.py
            ./scripts/android-battery-decode.proto
            ./scripts/android-cellular-compare.py
            ./scripts/android-cellular-capture.py
            ./scripts/android-battery-paired.py
          ];
        };
        androidBatteryDecoder = pkgs.writeShellApplication {
          name = "p2p-vpn-android-battery-decode";
          runtimeInputs = [
            androidBatteryPython
            pkgs.protobuf
          ];
          text = ''
            export PYTHONDONTWRITEBYTECODE=1
            exec python3 ${androidBatterySources}/android-battery-decode.py "$@"
          '';
        };
        androidBatteryDecoderTests =
          pkgs.runCommand "p2p-vpn-android-battery-decode-tests"
            {
              nativeBuildInputs = [
                androidBatteryPython
                pkgs.protobuf
              ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              export P2P_VPN_BATTERY_DECODER=${androidBatterySources}/android-battery-decode.py
              python3 ${./tests/android-battery-decode.py}
              touch "$out"
            '';
        androidCellularCompare = pkgs.writeShellApplication {
          name = "p2p-vpn-android-cellular-compare";
          runtimeInputs = [
            androidBatteryPython
            pkgs.protobuf
          ];
          text = ''
            export PYTHONDONTWRITEBYTECODE=1
            exec python3 ${androidBatterySources}/android-cellular-compare.py "$@"
          '';
        };
        androidCellularCompareTests =
          pkgs.runCommand "p2p-vpn-android-cellular-compare-tests"
            {
              nativeBuildInputs = [
                androidBatteryPython
                pkgs.protobuf
                pkgs.ruff
              ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              export P2P_VPN_CELLULAR_COMPARE=${androidBatterySources}/android-cellular-compare.py
              ruff check ${androidBatterySources}/android-cellular-compare.py ${./tests/android-cellular-compare.py}
              ruff format --check ${androidBatterySources}/android-cellular-compare.py ${./tests/android-cellular-compare.py}
              python3 ${./tests/android-cellular-compare.py}
              touch "$out"
            '';
        androidCellularCapture = pkgs.writeShellApplication {
          name = "p2p-vpn-android-cellular-capture";
          runtimeInputs = [
            androidBatteryPython
            pkgs.protobuf
            pkgs.android-tools
            pkgs.iproute2
            pkgs.iputils
          ];
          text = ''
            export PYTHONDONTWRITEBYTECODE=1
            exec python3 ${androidBatterySources}/android-cellular-capture.py "$@"
          '';
        };
        androidCellularCaptureTests =
          pkgs.runCommand "p2p-vpn-android-cellular-capture-tests"
            {
              nativeBuildInputs = [
                androidBatteryPython
                pkgs.protobuf
                pkgs.ruff
              ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              export P2P_VPN_CELLULAR_CAPTURE=${androidBatterySources}/android-cellular-capture.py
              ruff check ${androidBatterySources}/android-cellular-capture.py ${./tests/android-cellular-capture.py}
              ruff format --check ${androidBatterySources}/android-cellular-capture.py ${./tests/android-cellular-capture.py}
              python3 ${./tests/android-cellular-capture.py}
              touch "$out"
            '';
        androidBatteryPaired = pkgs.writeShellApplication {
          name = "p2p-vpn-android-battery-paired";
          runtimeInputs = [
            androidBatteryPython
            pkgs.protobuf
            pkgs.android-tools
          ];
          text = ''
            export PYTHONDONTWRITEBYTECODE=1
            exec python3 ${androidBatterySources}/android-battery-paired.py "$@"
          '';
        };
        androidBatteryPairedTests =
          pkgs.runCommand "p2p-vpn-android-battery-paired-tests"
            {
              nativeBuildInputs = [ androidBatteryPython ];
            }
            ''
              export PYTHONDONTWRITEBYTECODE=1
              export P2P_VPN_BATTERY_PAIRED=${androidBatterySources}/android-battery-paired.py
              python3 ${./tests/android-battery-paired.py}
              touch "$out"
            '';
        androidDeviceAuditRuntime =
          if androidSupported then
            pkgs.writeShellApplication {
              name = "p2p-vpn-android-device-audit";
              runtimeInputs = [
                android.androidSdk
                pkgs.bash
                pkgs.coreutils
                pkgs.gawk
                pkgs.gnugrep
                pkgs.gnused
                pkgs.iputils
                pkgs.jq
              ];
              text = ''
                export P2P_VPN_ADB=${android.androidSdk}/bin/adb
                export P2P_VPN_ANDROID_APK=${android.androidDebugApk}/p2p-vpn-debug.apk
                exec bash ${./scripts/android-device-audit.sh} "$@"
              '';
            }
          else
            null;
        androidDeviceAuditLauncher =
          if androidSupported then
            pkgs.writeShellApplication {
              name = "p2p-vpn-android-device-audit";
              runtimeInputs = [
                pkgs.bash
                pkgs.coreutils
                pkgs.gnugrep
                pkgs.gnused
              ];
              text = ''
                export P2P_VPN_ANDROID_E2E_FLAKE=${lib.escapeShellArg "path:${./.}"}
                export P2P_VPN_ANDROID_E2E_RUNTIME_TARGET=android-device-audit-runtime
                exec bash ${./scripts/android-e2e-nix.sh} "$@"
              '';
            }
          else
            null;
        androidE2eStructure =
          if androidSupported then
            pkgs.runCommand "p2p-vpn-android-e2e-structure"
              {
                nativeBuildInputs = [
                  pkgs.bash
                  pkgs.gawk
                  pkgs.coreutils
                  pkgs.gnugrep
                  pkgs.gnused
                  pkgs.jq
                  pkgs.shellcheck
                ];
              }
              ''
                shellcheck ${./scripts/android-e2e.sh}
                shellcheck ${./scripts/android-resource-isolation.sh}
                shellcheck ${./tests/android-resource-isolation.sh}
                shellcheck ${./scripts/android-process-sample.sh}
                shellcheck ${./scripts/android-power-capture.sh}
                shellcheck ${./tests/android-power-capture.sh}
                P2P_VPN_ANDROID_POWER_CAPTURE=${./scripts/android-power-capture.sh} \
                  bash ${./tests/android-power-capture.sh}
                shellcheck ${./scripts/android-resource-controls.sh}
                shellcheck ${./tests/android-resource-power.sh}
                shellcheck ${./tests/android-resource-sample.sh}
                shellcheck ${./tests/android-resource-window.sh}
                shellcheck ${./tests/android-resource-isolation-state.sh}
                P2P_VPN_ANDROID_RESOURCE_CONTROLS=${./scripts/android-resource-controls.sh} \
                  bash ${./tests/android-resource-isolation-state.sh}
                shellcheck ${./tests/android-resource-permissions.sh}
                shellcheck ${./tests/android-resource-traffic.sh}
                P2P_VPN_ANDROID_E2E_SCRIPT=${./scripts/android-e2e.sh} \
                  bash ${./tests/android-resource-traffic.sh}
                P2P_VPN_ANDROID_E2E_SCRIPT=${./scripts/android-e2e.sh} \
                  bash ${./tests/android-resource-permissions.sh}
                shellcheck ${./tests/android-resource-ping.sh}
                P2P_VPN_ANDROID_RESOURCE_CONTROLS=${./scripts/android-resource-controls.sh} \
                  bash ${./tests/android-resource-ping.sh}
                P2P_VPN_ANDROID_RESOURCE_CONTROLS=${./scripts/android-resource-controls.sh} \
                  bash ${./tests/android-resource-power.sh}
                P2P_VPN_ANDROID_RESOURCE_CONTROLS=${./scripts/android-resource-controls.sh} \
                  bash ${./tests/android-resource-sample.sh}
                P2P_VPN_ANDROID_RESOURCE_CONTROLS=${./scripts/android-resource-controls.sh} \
                  bash ${./tests/android-resource-window.sh}
                shellcheck ${./tests/android-process-sample.sh}
                shellcheck ${./tests/android-fixture-path-budget.sh}
                P2P_VPN_ANDROID_HARNESS=${./scripts/android-e2e.sh} \
                  bash ${./tests/android-fixture-path-budget.sh}
                shellcheck ${./scripts/android-e2e-nix.sh}

                source <(sed -n '/^summarize_android_connectivity() {$/,/^}$/p' ${./scripts/android-e2e.sh})
                printf '%s\n' 'Unrecognized connectivity output: private.example' \
                  | summarize_android_connectivity \
                  | jq -e '. == {status: "unsupported", networks: null}' >/dev/null
                printf '%s\n' 'Current Networks:' \
                  | summarize_android_connectivity \
                  | jq -e '. == {status: "parsed", networks: []}' >/dev/null
                source <(sed -n '/^ping_measurement() {$/,/^}$/p' ${./scripts/android-e2e.sh})
                printf '%s\n' \
                  '64 bytes from 100.64.0.9: icmp_seq=1 ttl=64 time=1.0 ms' \
                  'From private.example icmp_seq=2 Destination Host Unreachable' \
                  '64 bytes from 100.64.0.9: icmp_seq=3 ttl=64 time=1.0 ms' \
                  | ping_measurement /dev/stdin 100 \
                  | jq -e '
                    keys == ["finished_unix_millis", "reply_sequences", "started_unix_millis"] and
                    .started_unix_millis == 100 and .finished_unix_millis >= 100 and
                    .reply_sequences == [1, 3]
                  ' >/dev/null

                test_root="$TMPDIR/android-e2e-test"
                mkdir -p \
                  "$test_root/bin" \
                  "$test_root/launcher-runtime/bin" \
                  "$test_root/launcher-tmp" \
                  "$test_root/tmp" \
                  "$test_root/evidence" \
                  "$test_root/adb-timeout-evidence" \
                  "$test_root/persistence-evidence" \
                  "$test_root/pairing-evidence" \
                  "$test_root/runtime-budget-evidence" \
                  "$test_root/skip-evidence"
                touch "$test_root/fake.apk"

                cat > "$test_root/bin/fake-nix" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                mode="''${P2P_VPN_ANDROID_E2E_FAKE_NIX_MODE:-allowed}"
                log="''${P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG:?}"
                runtime="''${P2P_VPN_ANDROID_E2E_FAKE_RUNTIME:?}"
                printf '%q ' "$@" >> "$log"
                printf '\n' >> "$log"

                if [[ "''${1:-}" == store && "''${2:-}" == info ]]; then
                  [[ "$mode" != cache-fail ]]
                  exit
                fi

                if [[ "''${1:-}" == config && "''${2:-}" == show \
                  && "''${3:-}" == trusted-public-keys ]]; then
                  printf '%s\n' \
                    'cache.nixos.org-1:test nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs='
                  exit 0
                fi

                if [[ "''${1:-}" == derivation && "''${2:-}" == show ]]; then
                  case "''${3:-}" in
                    *.zip.drv)
                      printf '%s\n' '{"derivations":{"source":{"outputs":{"out":{"hash":"sha256-test"}}}}}'
                      ;;
                    *yasna-0.5.2.drv)
                      printf '%s\n' '{"derivations":{"crate":{"env":{"buildCommand":"extract .cargo-checksum.json"},"outputs":{"out":{"path":"test"}}}}}'
                      ;;
                    *maven-metadata.xml.drv)
                      printf '%s\n' '{"derivations":{"metadata":{"env":{"allowSubstitutes":"","buildCommand":"target=$out$destination\nprintf \"%s\" \"$text\" > \"$target\"\n","buildInputs":"","name":"maven-metadata.xml","nativeBuildInputs":"","preferLocalBuild":"1","text":"<?xml version=\"1.0\"?><metadata/>"},"outputs":{"out":{"path":"test"}}}}}'
                      ;;
                    *)
                      printf '%s\n' '{"derivations":{"package":{"outputs":{"out":{"path":"test"}}}}}'
                      ;;
                  esac
                  exit 0
                fi

                if [[ "''${1:-}" == build && " $* " == *' --dry-run '* ]]; then
                  printf 'these 4 derivations will be built:\n' >&2
                  printf '  /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-p2p-vpn-android-e2e.drv\n' >&2
                  printf '  /nix/store/cccccccccccccccccccccccccccccccc-yasna-0.5.2.drv\n' >&2
                  printf '  /nix/store/dddddddddddddddddddddddddddddddd-maven-metadata.xml.drv\n' >&2
                  if [[ "$mode" == dangerous ]]; then
                    printf '  /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-gcc-15.3.0.drv\n' >&2
                  else
                    printf '  /nix/store/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb-emulator.zip.drv\n' >&2
                  fi
                  exit 0
                fi

                if [[ "''${1:-}" == build ]]; then
                  if [[ "$mode" == fast-budget ]]; then
                    : "''${P2P_VPN_ANDROID_E2E_FAKE_DF_TRIGGER:?}"
                    touch "$P2P_VPN_ANDROID_E2E_FAKE_DF_TRIGGER"
                    printf '%s\n' "$runtime"
                    exit 0
                  fi
                  if [[ "$mode" == budget && " $* " == *' --print-out-paths '* ]]; then
                    trap 'exit 143' TERM
                    sleep 30
                    exit 1
                  fi
                  printf '%s\n' "$runtime"
                  exit 0
                fi

                exit 2
                EOF
                chmod +x "$test_root/bin/fake-nix"

                cat > "$test_root/launcher-runtime/bin/p2p-vpn-android-e2e" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                printf '%s\n' "$*" > "''${P2P_VPN_ANDROID_E2E_FAKE_RUNTIME_LOG:?}"
                EOF
                chmod +x "$test_root/launcher-runtime/bin/p2p-vpn-android-e2e"
                cat > "$test_root/launcher-runtime/bin/p2p-vpn-android-device-audit" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                printf '%s\n' "$*" > "''${P2P_VPN_ANDROID_E2E_FAKE_RUNTIME_LOG:?}"
                EOF
                chmod +x "$test_root/launcher-runtime/bin/p2p-vpn-android-device-audit"

                launcher_log="$test_root/launcher-nix.log"
                launcher_runtime_log="$test_root/launcher-runtime.log"
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME_LOG="$launcher_runtime_log" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --scenario boot-smoke
                grep -Fx -- '--scenario boot-smoke' "$launcher_runtime_log"
                grep -F -- '--dry-run' "$launcher_log"
                grep -F -- 'emulator.zip.drv\^\*' "$launcher_log"
                grep -F -- '--print-out-paths' "$launcher_log"
                grep -F -- '--option max-jobs 2' "$launcher_log"
                grep -F -- '--option substituters https://cache.nixos.org\ https://nix-community.cachix.org' \
                  "$launcher_log"
                ! grep -F -- 'niri.cachix.org' "$launcher_log"
                test -z "$(find "$test_root/launcher-tmp" -maxdepth 1 \
                  -name 'p2p-vpn-android-e2e-plan.*' -print -quit)"

                : > "$launcher_log"
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_RUNTIME_TARGET=android-device-audit-runtime \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME_LOG="$launcher_runtime_log" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --preflight
                grep -Fx -- '--preflight' "$launcher_runtime_log"
                grep -F -- 'path:/fake#android-device-audit-runtime' "$launcher_log"
                test -z "$(find "$test_root/launcher-tmp" -maxdepth 1 \
                  -name 'p2p-vpn-android-e2e-plan.*' -print -quit)"

                : > "$launcher_log"
                set +e
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_MODE=dangerous \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --scenario boot-smoke
                launcher_status=$?
                set -e
                test "$launcher_status" -eq 75
                grep -F -- '--dry-run' "$launcher_log"
                ! grep -F -- '--print-out-paths' "$launcher_log"

                cat > "$test_root/bin/fake-df" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                state="''${P2P_VPN_ANDROID_E2E_FAKE_DF_STATE:?}"
                trigger="''${P2P_VPN_ANDROID_E2E_FAKE_DF_TRIGGER:-}"
                count=0
                if [[ -f "$state" ]]; then
                  read -r count < "$state"
                fi
                count=$((count + 1))
                printf '%s\n' "$count" > "$state"
                available=100000000000
                if [[ -n "$trigger" && -f "$trigger" ]]; then
                  available=$((available - 2097152))
                elif ((count > 2)); then
                  available=$((available - 2097152))
                fi
                printf 'Avail\n%s\n' "$available"
                EOF
                chmod +x "$test_root/bin/fake-df"

                : > "$launcher_log"
                set +e
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_DF="$test_root/bin/fake-df" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_MAX_STORE_GROWTH_BYTES=1048576 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_MODE=budget \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  P2P_VPN_ANDROID_E2E_FAKE_DF_STATE="$test_root/fake-df-state" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --scenario boot-smoke
                launcher_status=$?
                set -e
                test "$launcher_status" -eq 75
                grep -F -- 'emulator.zip.drv\^\*' "$launcher_log"
                ! grep -F -- '--print-out-paths' "$launcher_log"
                test -z "$(find "$test_root/launcher-tmp" -maxdepth 1 \
                  -name 'p2p-vpn-android-e2e-plan.*' -print -quit)"

                : > "$launcher_log"
                rm -f "$test_root/fast-budget-trigger" "$test_root/fast-df-state"
                set +e
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_DF="$test_root/bin/fake-df" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_MAX_STORE_GROWTH_BYTES=1048576 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_MODE=fast-budget \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  P2P_VPN_ANDROID_E2E_FAKE_DF_STATE="$test_root/fast-df-state" \
                  P2P_VPN_ANDROID_E2E_FAKE_DF_TRIGGER="$test_root/fast-budget-trigger" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --scenario boot-smoke
                launcher_status=$?
                set -e
                test "$launcher_status" -eq 75
                grep -F -- 'emulator.zip.drv\^\*' "$launcher_log"
                ! grep -F -- '--print-out-paths' "$launcher_log"
                test -z "$(find "$test_root/launcher-tmp" -maxdepth 1 \
                  -name 'p2p-vpn-android-e2e-plan.*' -print -quit)"

                : > "$launcher_log"
                set +e
                P2P_VPN_ANDROID_E2E_NIX="$test_root/bin/fake-nix" \
                  P2P_VPN_ANDROID_E2E_FLAKE=path:/fake \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_MODE=cache-fail \
                  P2P_VPN_ANDROID_E2E_FAKE_NIX_LOG="$launcher_log" \
                  P2P_VPN_ANDROID_E2E_FAKE_RUNTIME="$test_root/launcher-runtime" \
                  TMPDIR="$test_root/launcher-tmp" \
                  bash ${./scripts/android-e2e-nix.sh} --scenario boot-smoke
                launcher_status=$?
                set -e
                test "$launcher_status" -eq 69
                ! grep -F -- 'build ' "$launcher_log"

                cat > "$test_root/bin/fake-emulator" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                ready_file="''${P2P_VPN_ANDROID_EMULATOR_READY_FILE:?}"
                trap 'exit 0' INT TERM
                printf 'Sending adb public key test-user@test-host\n'
                printf 'Crash data: /tmp/android-test-user/crash.db\n'
                if [[ -n "''${P2P_VPN_ANDROID_E2E_FAKE_STORAGE_TRIGGER:-}" ]]; then
                  touch "$P2P_VPN_ANDROID_E2E_FAKE_STORAGE_TRIGGER"
                  while :; do sleep 1; done
                fi
                printf 'emulator-test\n' > "$ready_file.tmp"
                mv "$ready_file.tmp" "$ready_file"
                while :; do sleep 1; done
                EOF
                chmod +x "$test_root/bin/fake-emulator"

                cat > "$test_root/bin/fake-runtime-df" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                trigger="''${P2P_VPN_ANDROID_E2E_FAKE_STORAGE_TRIGGER:?}"
                available=100000000000
                if [[ -f "$trigger" ]]; then
                  available=$((available - 2097152))
                fi
                printf 'Avail\n%s\n' "$available"
                EOF
                chmod +x "$test_root/bin/fake-runtime-df"

                cat > "$test_root/bin/fake-fixture" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                traffic_state="''${P2P_VPN_ANDROID_E2E_FAKE_TRAFFIC_STATE:-}"
                promotion_state="''${P2P_VPN_ANDROID_E2E_FAKE_PROMOTION_STATE:-}"
                record_fake_traffic() {
                  [[ -n "$traffic_state" ]] || return 0
                  current=0
                  if [[ -s "$traffic_state" ]]; then current="$(< "$traffic_state")"; fi
                  printf '%d\n' "$((current + $1))" > "$traffic_state"
                }
                case "''${1:-}" in
                  run)
                    shift
                    state_dir=""
                    network=android-e2e
                    path_mode=automatic
                    while [[ $# -gt 0 ]]; do
                      case "$1" in
                        --state-dir) state_dir="$2"; shift 2 ;;
                        --network) network="$2"; shift 2 ;;
                        --path-mode) path_mode="$2"; shift 2 ;;
                        *) shift ;;
                      esac
                    done
                    : "''${state_dir:?}"
                    mkdir -p "$state_dir"
                    touch "$state_dir/peer-control.sock" "$state_dir/packet-control.sock"
                    jq -n \
                      --arg control "$state_dir/peer-control.sock" \
                      --arg packet "$state_dir/packet-control.sock" \
                      --arg network "$network" \
                      --arg path_mode "$path_mode" \
                      '{
                        schema_version: 1,
                        network: $network,
                        path_mode: $path_mode,
                        bootstrap: {
                          peer_id: "12D3KooWFakeBootstrapPeer",
                          android_address: "/ip4/10.0.2.2/tcp/42300/p2p/12D3KooWFakeBootstrapPeer",
                          kademlia_protocol: "/p2p-vpn/kad/1"
                        },
                        peer: {
                          peer_id: "12D3KooWFakeLinuxPeer",
                          pairing_android_address: (
                            if ($path_mode == "relay-only" or $path_mode == "relay-to-direct") then
                              null
                            elif $path_mode == "quic-stream" then
                              "/ip4/10.0.2.2/udp/42302/quic-v1/p2p/12D3KooWFakeLinuxPeer"
                            else
                              "/ip4/10.0.2.2/tcp/42301/p2p/12D3KooWFakeLinuxPeer"
                            end
                          ),
                          ipv4: "100.64.0.2",
                          ipv6: "fd42::2",
                          control_socket: $control
                        },
                        packet_control_socket: $packet
                    } + (if $path_mode == "owned-quic" then {
                        owned_quic: {
                          android_listen: "0.0.0.0:42304",
                          android_external_endpoint: "127.0.0.1:42304",
                          host_forward_port: 42304,
                          guest_listen_port: 42304
                        }
                      } else {} end) +
                      (if ($path_mode == "relay-only" or $path_mode == "relay-to-direct") then {
                        relay: {
                          android_reservation: "/ip4/10.0.2.2/tcp/42300/p2p/12D3KooWFakeBootstrapPeer/p2p-circuit"
                        }
                      } else {} end) +
                      (if $path_mode == "relay-to-direct" then {
                        promotion: {direct_path: "tcp_stream"}
                      } else {} end)' > "$state_dir/fixture.json.pending"
                    mv "$state_dir/fixture.json.pending" "$state_dir/fixture.json"
                    printf 'private state: %s code ABCD-EFGH-JKLM-NPQR\n' "$state_dir"
                    printf 'ControlCapabilities { membership_tag: Some("secret-tag"), owned_quic_packet_plane_certificate_der: Some([1, 2]), member_public_key: "secret-key", signature: "secret-signature" }\n'
                    printf 'underlay 192.0.2.44 [fd00::44]:42300 /dns4/private.example/udp/42300\n'
                    printf 'peer 12D3KooWFakeFixturePeer legacy-peer=QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN overlay=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef key /members/c2VjcmV0+/membership-records/1\n'
                    trap 'exit 0' INT TERM
                    while :; do sleep 1; done
                    ;;
                  probe)
                    family=ipv4
                    count=5
                    while [[ $# -gt 0 ]]; do
                      if [[ "$1" == --source && "''${2:-}" == *:* ]]; then family=ipv6; fi
                      if [[ "$1" == --count ]]; then count="$2"; fi
                      shift
                    done
                    record_fake_traffic "$count"
                    jq -cn --arg family "$family" --argjson count "$count" \
                      '{schema_version: 1, ok: true, family: $family, sent: $count, received: $count}'
                    ;;
                  enable-direct)
                    : "''${promotion_state:?}"
                    current=0
                    if [[ -s "$traffic_state" ]]; then current="$(< "$traffic_state")"; fi
                    printf '%d\n' "$current" > "$promotion_state"
                    jq -cn '{schema_version: 1, ok: true, enabled: true, already_enabled: false}'
                    ;;
                  *) exit 2 ;;
                esac
                EOF
                chmod +x "$test_root/bin/fake-fixture"

                cat > "$test_root/bin/fake-p2p-vpn" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                path_mode="''${P2P_VPN_ANDROID_E2E_FAKE_PATH_MODE:-automatic}"
                traffic_state="''${P2P_VPN_ANDROID_E2E_FAKE_TRAFFIC_STATE:-}"
                promotion_state="''${P2P_VPN_ANDROID_E2E_FAKE_PROMOTION_STATE:-}"
                case "$*" in
                  'daemon-state '* )
                    current=0
                    if [[ -s "$traffic_state" ]]; then current="$(< "$traffic_state")"; fi
                    if [[ "$path_mode" == relay-only ]]; then
                      printf '%s\n' \
                        'peer state: fake transport 12D3KooWFakeAndroidPeer validated true selected_path circuit_relay selected_path_score 30 selected_path_mtu 1000 selected_path_origin relay_circuit healthy_paths 1 direct_paths 0 relay_paths 1' \
                        'outbound_stream_fallback_packets 24' \
                        'relay_inbound_circuits_established 2' \
                        'relay_outbound_circuits_established 0'
                    elif [[ "$path_mode" == relay-to-direct ]]; then
                      if [[ -s "$promotion_state" ]]; then
                        baseline="$(< "$promotion_state")"
                        printf '%s\n' \
                          'peer state: fake transport 12D3KooWFakeAndroidPeer validated true selected_path direct_tcp_stream selected_path_score 60 selected_path_mtu 1280 selected_path_origin identify healthy_paths 2 direct_paths 1 relay_paths 1' \
                          "outbound_stream_fallback_packets $baseline" \
                          "outbound_direct_tcp_stream_fallback_packets $((current - baseline))" \
                          'path_promotions_to_direct 1' \
                          'relay_inbound_circuits_established 2' \
                          'relay_outbound_circuits_established 0'
                      else
                        printf '%s\n' \
                          'peer state: fake transport 12D3KooWFakeAndroidPeer validated true selected_path circuit_relay selected_path_score 30 selected_path_mtu 1000 selected_path_origin relay_circuit healthy_paths 1 direct_paths 0 relay_paths 1' \
                          "outbound_stream_fallback_packets $current" \
                          'outbound_direct_tcp_stream_fallback_packets 0' \
                          'path_promotions_to_direct 0' \
                          'relay_inbound_circuits_established 2' \
                          'relay_outbound_circuits_established 0'
                      fi
                    else
                      printf '%s\n' \
                        'peer state: fake transport 12D3KooWFakeAndroidPeer validated true selected_path direct_tcp_stream selected_path_score 60 selected_path_mtu 1280 selected_path_origin identify healthy_paths 1 direct_paths 1 relay_paths 0'
                    fi
                    ;;
                  'pair open '* )
                    jq -cn '{operation_id: "fake-operation", code: "ABCD-EFGH-JKLM-NPQR"}'
                    ;;
                  'pair status fake-operation '* )
                    jq -cn '{
                      operation_id: "fake-operation",
                      phase: "awaiting_approval",
                      candidate: {
                        approval_id: "fake-approval",
                        peer_id: "12D3KooWFakeAndroidPeer",
                        requested_hostname: "android-0123456789abcdef"
                      }
                    }'
                    ;;
                  'pair approve fake-operation fake-approval '* )
                    jq -cn '{operation_id: "fake-operation", phase: "completed"}'
                    ;;
                  *) exit 2 ;;
                esac
                EOF
                chmod +x "$test_root/bin/fake-p2p-vpn"

                cat > "$test_root/bin/fake-adb" <<'EOF'
                #!${pkgs.bash}/bin/bash
                set -euo pipefail
                if [[ "''${1:-}" == -s ]]; then shift 2; fi
                if [[ "''${P2P_VPN_ANDROID_E2E_FAKE_ADB_HANG:-}" == logcat \
                  && "''${1:-}" == logcat ]]; then
                  sleep 300
                fi
                pairing_state="''${P2P_VPN_ANDROID_E2E_FAKE_PAIRING_STATE:-}"
                always_on_state="''${P2P_VPN_ANDROID_E2E_FAKE_ALWAYS_ON_STATE:-}"
                path_mode="''${P2P_VPN_ANDROID_E2E_FAKE_PATH_MODE:-automatic}"
                traffic_state="''${P2P_VPN_ANDROID_E2E_FAKE_TRAFFIC_STATE:-}"
                promotion_state="''${P2P_VPN_ANDROID_E2E_FAKE_PROMOTION_STATE:-}"
                underlay_state="''${P2P_VPN_ANDROID_E2E_FAKE_UNDERLAY_STATE:-}"
                record_fake_traffic() {
                  [[ -n "$traffic_state" ]] || return 0
                  current=0
                  if [[ -s "$traffic_state" ]]; then current="$(< "$traffic_state")"; fi
                  printf '%d\n' "$((current + $1))" > "$traffic_state"
                }
                case "$*" in
                  get-state) printf 'device\n' ;;
                  emu\ redir\ add\ udp:*) ;;
                  'shell getprop ro.build.version.sdk') printf '35\n' ;;
                  'shell getprop ro.product.cpu.abi') printf 'x86_64\n' ;;
                  'shell pm path org.hermeticfoundation.p2pvpn.debug')
                    printf 'package:/data/app/p2p-vpn/base.apk\n'
                    ;;
                  'shell dumpsys activity activities')
                    printf 'org.hermeticfoundation.p2pvpn.MainActivity\n'
                    ;;
                  'shell dumpsys connectivity')
                    printf '%s\n' \
                      'Current Networks:' \
                      '  NetworkAgentInfo{network{100} ni{WIFI CONNECTED} lp{192.0.2.44 private.example} nc{[ Transports: WIFI Capabilities: INTERNET&NOT_VPN&VALIDATED]}}' \
                      '  NetworkAgentInfo{network{101} ni{MOBILE CONNECTED} nc{[ Transports: CELLULAR Capabilities: INTERNET&NOT_VPN]}}' \
                      '  NetworkAgentInfo{network{102} nc{[ Transports: WIFI|VPN Capabilities: INTERNET&VALIDATED]}}' \
                      '  NetworkAgentInfo{network{103} nc{[ Transports: VPN|CELLULAR Capabilities: INTERNET]}}' \
                      '  NetworkOffer [ Transports: WIFI Capabilities: INTERNET&VALIDATED ]'
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command status')
                    if [[ -n "$pairing_state" && -f "$pairing_state" ]]; then
                      state="$(< "$pairing_state")"
                      connected=false
                      pairing_detail='No pairing operation'
                      connected_peers=0
                      direct_quic_datagram=0
                      direct_quic_stream=0
                      direct_tcp_stream=0
                      relay=0
                      packet_plane_quic_sessions=0
                      outbound_quic_datagram_packets=0
                      outbound_direct_tcp_stream_packets=0
                      promotions_to_direct=0
                      runtime_generation=0
                      underlay_kind=wifi
                      underlay_validated=true
                      underlay_available_networks=2
                      underlay_selection_changes=0
                      underlay_selected_losses=0
                      underlay_recoveries=0
                      underlay_runtime_recovery_requests=0
                      underlay_runtime_recovery_failures=0
                      if [[ -n "$underlay_state" && -s "$underlay_state" ]]; then
                        case "$(< "$underlay_state")" in
                          cellular)
                            underlay_kind=cellular
                            underlay_available_networks=1
                            underlay_selection_changes=1
                            underlay_selected_losses=1
                            underlay_runtime_recovery_requests=1
                            ;;
                          none)
                            underlay_kind=none
                            underlay_validated=false
                            underlay_available_networks=0
                            underlay_selection_changes=2
                            underlay_selected_losses=2
                            underlay_runtime_recovery_requests=2
                            ;;
                          recovered-cellular)
                            underlay_kind=cellular
                            underlay_available_networks=1
                            underlay_selection_changes=3
                            underlay_selected_losses=2
                            underlay_recoveries=1
                            underlay_runtime_recovery_requests=3
                            ;;
                          restored-wifi)
                            underlay_selection_changes=4
                            underlay_selected_losses=2
                            underlay_recoveries=1
                            underlay_runtime_recovery_requests=4
                            ;;
                          *) exit 2 ;;
                        esac
                      fi
                      if [[ "$state" == connected || "$state" == paired ]]; then
                        connected=true
                        runtime_generation=1
                      fi
                      if [[ "$state" == paired ]]; then
                        runtime_generation=2
                        pairing_detail='Paired with 12D3KooWFakeLinuxPeer'
                        connected_peers=1
                        case "$path_mode" in
                          quic-stream) direct_quic_stream=1 ;;
                          owned-quic)
                            direct_quic_datagram=1
                            direct_quic_stream=1
                            direct_tcp_stream=1
                            packet_plane_quic_sessions=1
                            if [[ -s "$traffic_state" ]]; then
                              outbound_quic_datagram_packets="$(< "$traffic_state")"
                            fi
                            ;;
                          relay-only)
                            relay=1
                            ;;
                          relay-to-direct)
                            if [[ -s "$promotion_state" ]]; then
                              baseline="$(< "$promotion_state")"
                              current=0
                              if [[ -s "$traffic_state" ]]; then current="$(< "$traffic_state")"; fi
                              direct_tcp_stream=1
                              relay=1
                              outbound_direct_tcp_stream_packets=$((current - baseline))
                              promotions_to_direct=1
                            else
                              relay=1
                            fi
                            ;;
                          *) direct_tcp_stream=1 ;;
                        esac
                      fi
                      network_phase=stopped
                      if [[ "$connected" == true ]]; then
                        network_phase=starting
                        if [[ -s "$pairing_state.runtime-phase" ]]; then
                          network_phase=running
                        fi
                        printf '%s\n' "$network_phase" > "$pairing_state.runtime-phase"
                      fi
                      response="$(jq -cn \
                        --argjson connected "$connected" \
                        --arg network_phase "$network_phase" \
                        --arg pairing_detail "$pairing_detail" \
                        --argjson connected_peers "$connected_peers" \
                        --argjson direct_quic_datagram "$direct_quic_datagram" \
                        --argjson direct_quic_stream "$direct_quic_stream" \
                        --argjson direct_tcp_stream "$direct_tcp_stream" \
                        --argjson relay "$relay" \
                        --argjson packet_plane_quic_sessions "$packet_plane_quic_sessions" \
                        --argjson outbound_quic_datagram_packets "$outbound_quic_datagram_packets" \
                        --argjson outbound_direct_tcp_stream_packets "$outbound_direct_tcp_stream_packets" \
                        --argjson promotions_to_direct "$promotions_to_direct" \
                        --argjson runtime_generation "$runtime_generation" \
                        --arg underlay_kind "$underlay_kind" \
                        --argjson underlay_validated "$underlay_validated" \
                        --argjson underlay_available_networks "$underlay_available_networks" \
                        --argjson underlay_selection_changes "$underlay_selection_changes" \
                        --argjson underlay_selected_losses "$underlay_selected_losses" \
                        --argjson underlay_recoveries "$underlay_recoveries" \
                        --argjson underlay_runtime_recovery_requests "$underlay_runtime_recovery_requests" \
                        --argjson underlay_runtime_recovery_failures "$underlay_runtime_recovery_failures" \
                        '{
                          schema_version: 1,
                          ok: true,
                          value: {
                            service_ready: true,
                            snapshot: {
                              has_profile: true,
                              profile_stored: true,
                              busy: false,
                              connected: $connected,
                              networks: [{selected: true, enabled: true, phase: $network_phase}],
                              network_name: "android-e2e",
                              hostname: "android-0123456789abcdef",
                              peer_id: "12D3KooWFakeAndroidPeer",
                              addresses: ["100.64.0.9/32", "fd42::9/128"],
                              pairing_detail: $pairing_detail,
                              runtime_generation: $runtime_generation,
                              underlay: {
                                kind: $underlay_kind,
                                validated: $underlay_validated,
                                available_networks: $underlay_available_networks,
                                selection_changes: $underlay_selection_changes,
                                selected_losses: $underlay_selected_losses,
                                recoveries: $underlay_recoveries,
                                runtime_recovery_requests: $underlay_runtime_recovery_requests,
                                runtime_recovery_failures: $underlay_runtime_recovery_failures
                              },
                              paths: {
                                connected_peers: $connected_peers,
                                direct_udp_datagram: 0,
                                direct_quic_datagram: $direct_quic_datagram,
                                direct_quic_stream: $direct_quic_stream,
                                direct_tcp_stream: $direct_tcp_stream,
                                relay: $relay,
                                public_routing_peers: 0,
                                packet_plane_quic_sessions: $packet_plane_quic_sessions,
                                outbound_quic_datagram_packets: $outbound_quic_datagram_packets,
                                outbound_direct_tcp_stream_packets: $outbound_direct_tcp_stream_packets,
                                promotions_to_direct: $promotions_to_direct
                              }
                            }
                          }
                        }')"
                    elif [[ -n "''${P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE:-}" \
                      && -f "$P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE" ]]; then
                      connected=false
                      connection_requested=false
                      always_on=false
                      lockdown=false
                      connection_detail='Disconnected'
                      runtime_generation=0
                      if [[ -n "$always_on_state" && -s "$always_on_state" ]]; then
                        connection_requested=true
                        case "$(< "$always_on_state")" in
                          manual)
                            connected=true
                            connection_detail='Connected'
                            runtime_generation=1
                            ;;
                          always-on|updated)
                            connected=true
                            always_on=true
                            connection_detail='Always-on VPN is managed by Android'
                            runtime_generation=1
                            ;;
                          lockdown)
                            always_on=true
                            lockdown=true
                            connection_detail='Turn off Block connections without VPN. p2p-vpn uses split-tunnel routes.'
                            runtime_generation=1
                            ;;
                          restored)
                            connected=true
                            always_on=true
                            connection_detail='Connected'
                            runtime_generation=2
                            ;;
                          *) exit 2 ;;
                        esac
                      fi
                      response="$(jq -cn \
                        --argjson connected "$connected" \
                        --argjson connection_requested "$connection_requested" \
                        --argjson always_on "$always_on" \
                        --argjson lockdown "$lockdown" \
                        --arg connection_detail "$connection_detail" \
                        --argjson runtime_generation "$runtime_generation" \
                        '{schema_version: 1, ok: true, value: {service_ready: true, snapshot: {
                          has_profile: true,
                          profile_stored: true,
                          busy: false,
                          connected: $connected,
                          connection_requested: $connection_requested,
                          always_on: $always_on,
                          lockdown: $lockdown,
                          connection_detail: $connection_detail,
                          network_name: "android-e2e",
                          hostname: "android-0123456789abcdef",
                          peer_id: "12D3KooWFakeAndroidPeer",
                          addresses: ["100.64.0.9/32", "fd42::9/128"],
                          runtime_generation: $runtime_generation,
                          paths: {connected_peers: 0}
                        }}}')"
                    else
                      response='{"schema_version":1,"ok":true,"value":{"service_ready":true,"snapshot":{"has_profile":false,"profile_stored":false,"addresses":[],"paths":{"connected_peers":0}}}}'
                    fi
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command diagnostics')
                    profile_stored=false
                    connection_requested=false
                    connected=false
                    always_on=false
                    lockdown=false
                    runtime_generation=0
                    connected_peers=0
                    direct_quic_datagram=0
                    direct_quic_stream=0
                    direct_tcp_stream=0
                    relay=0
                    packet_plane_quic_sessions=0
                    promotions_to_direct=0
                    if [[ -n "$pairing_state" && -f "$pairing_state" ]]; then
                      profile_stored=true
                      state="$(< "$pairing_state")"
                      if [[ "$state" == connected || "$state" == paired ]]; then
                        connection_requested=true
                        connected=true
                        runtime_generation=1
                      fi
                      if [[ "$state" == paired ]]; then
                        runtime_generation=2
                        connected_peers=1
                        case "$path_mode" in
                          quic-stream) direct_quic_stream=1 ;;
                          owned-quic)
                            direct_quic_datagram=1
                            direct_quic_stream=1
                            direct_tcp_stream=1
                            packet_plane_quic_sessions=1
                            ;;
                          relay-only) relay=1 ;;
                          relay-to-direct)
                            if [[ -s "$promotion_state" ]]; then
                              direct_tcp_stream=1
                              relay=1
                              promotions_to_direct=1
                            else
                              relay=1
                            fi
                            ;;
                          *) direct_tcp_stream=1 ;;
                        esac
                      fi
                    elif [[ -n "''${P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE:-}" \
                      && -f "$P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE" ]]; then
                      profile_stored=true
                      if [[ -n "$always_on_state" && -s "$always_on_state" ]]; then
                        case "$(< "$always_on_state")" in
                          manual)
                            connection_requested=true
                            connected=true
                            runtime_generation=1
                            ;;
                          always-on|updated)
                            connection_requested=true
                            connected=true
                            always_on=true
                            runtime_generation=1
                            ;;
                          lockdown)
                            connection_requested=true
                            always_on=true
                            lockdown=true
                            runtime_generation=1
                            ;;
                          restored)
                            connection_requested=true
                            connected=true
                            always_on=true
                            runtime_generation=2
                            ;;
                          *) exit 2 ;;
                        esac
                      fi
                    fi

                    underlay_kind=wifi
                    underlay_validated=true
                    underlay_available_networks=2
                    underlay_selection_changes=0
                    underlay_selected_losses=0
                    underlay_recoveries=0
                    underlay_runtime_recovery_requests=0
                    if [[ -n "$underlay_state" && -s "$underlay_state" ]]; then
                      case "$(< "$underlay_state")" in
                        cellular)
                          underlay_kind=cellular
                          underlay_available_networks=1
                          underlay_selection_changes=1
                          underlay_selected_losses=1
                          underlay_runtime_recovery_requests=1
                          ;;
                        none)
                          underlay_kind=none
                          underlay_validated=false
                          underlay_available_networks=0
                          underlay_selection_changes=2
                          underlay_selected_losses=2
                          underlay_runtime_recovery_requests=2
                          ;;
                        recovered-cellular)
                          underlay_kind=cellular
                          underlay_available_networks=1
                          underlay_selection_changes=3
                          underlay_selected_losses=2
                          underlay_recoveries=1
                          underlay_runtime_recovery_requests=3
                          ;;
                        restored-wifi)
                          underlay_selection_changes=4
                          underlay_selected_losses=2
                          underlay_recoveries=1
                          underlay_runtime_recovery_requests=4
                          ;;
                        *) exit 2 ;;
                      esac
                    fi

                    report="$(jq -cn \
                      --argjson profile_stored "$profile_stored" \
                      --argjson connection_requested "$connection_requested" \
                      --argjson connected "$connected" \
                      --argjson always_on "$always_on" \
                      --argjson lockdown "$lockdown" \
                      --argjson runtime_generation "$runtime_generation" \
                      --argjson connected_peers "$connected_peers" \
                      --argjson direct_quic_datagram "$direct_quic_datagram" \
                      --argjson direct_quic_stream "$direct_quic_stream" \
                      --argjson direct_tcp_stream "$direct_tcp_stream" \
                      --argjson relay "$relay" \
                      --argjson packet_plane_quic_sessions "$packet_plane_quic_sessions" \
                      --argjson promotions_to_direct "$promotions_to_direct" \
                      --arg underlay_kind "$underlay_kind" \
                      --argjson underlay_validated "$underlay_validated" \
                      --argjson underlay_available_networks "$underlay_available_networks" \
                      --argjson underlay_selection_changes "$underlay_selection_changes" \
                      --argjson underlay_selected_losses "$underlay_selected_losses" \
                      --argjson underlay_recoveries "$underlay_recoveries" \
                      --argjson underlay_runtime_recovery_requests "$underlay_runtime_recovery_requests" \
                      '{
                        schema_version: 1,
                        kind: "p2p-vpn-android-diagnostics",
                        generated_at: "2026-08-30T12:00:00Z",
                        app: {version: "0.1.0-debug", android_api: 35},
                        lifecycle: {
                          service_uptime_millis: 12000,
                          profile_stored: $profile_stored,
                          profile_readable: $profile_stored,
                          connection_requested: $connection_requested,
                          connected: $connected,
                          always_on: $always_on,
                          lockdown: $lockdown,
                          busy: false,
                          runtime_generation: $runtime_generation
                        },
                        underlay: {
                          kind: $underlay_kind,
                          validated: $underlay_validated,
                          available_networks: $underlay_available_networks,
                          selection_changes: $underlay_selection_changes,
                          selected_losses: $underlay_selected_losses,
                          recoveries: $underlay_recoveries,
                          runtime_recovery_requests: $underlay_runtime_recovery_requests,
                          runtime_recovery_failures: 0
                        },
                        paths: {
                          connected_peers: $connected_peers,
                          peers_without_supported_path: 0,
                          direct_udp_datagram: 0,
                          direct_quic_datagram: $direct_quic_datagram,
                          direct_quic_stream: $direct_quic_stream,
                          direct_tcp_stream: $direct_tcp_stream,
                          relay: $relay,
                          public_routing_peers: 0,
                          packet_plane_quic_sessions: $packet_plane_quic_sessions,
                          promotions_to_direct: $promotions_to_direct
                        },
                        queue: {
                          queued_packets: 0,
                          queued_bytes: 0,
                          oldest_packet_age_millis: 0,
                          blocked_no_supported_path_events: 0,
                          blocked_packet_window_events: 0
                        },
                        drops: {
                          queue_packets: 0,
                          queue_bytes: 0,
                          expired_packets: 0,
                          expired_bytes: 0,
                          outbound_packets: 0,
                          inbound_packets: 0,
                          packet_plane_datagrams: 0,
                          path_fallbacks_to_relay: 0,
                          packet_plane_path_demotions: 0,
                          stream_path_demotions: 0
                        },
                        traffic: {
                          inbound_accepted_packets: 0,
                          outbound_owned_quic_datagram_packets: 0,
                          outbound_sent_packets: 0,
                          tun_read_packets: 0,
                          tun_write_packets: 0
                        },
                        resources: {
                          process_cpu_millis: 150,
                          total_pss_kib: 4096,
                          private_dirty_kib: 2048,
                          java_heap_used_bytes: 1048576,
                          java_heap_max_bytes: 16777216,
                          active_threads: 8
                        },
                        pairing: {operation_active: false, candidate_pending: false},
                        events: {
                          discarded: 0,
                          items: [
                            {sequence: 1, since_service_start_millis: 0, name: "service_created"},
                            {sequence: 2, since_service_start_millis: 12000, name: "diagnostic_report_generated"}
                          ]
                        },
                        privacy: {
                          identity_material: "excluded",
                          peers: "excluded",
                          pairing_secrets: "excluded",
                          underlay_addresses: "excluded"
                        }
                      }')"
                    response="$(jq -cn --argjson report "$report" \
                      '{schema_version: 1, ok: true, value: {service_ready: true, report: $report}}')"
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command create-profile --es network android-e2e')
                    : "''${P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE:?}"
                    touch "$P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE"
                    response='{"schema_version":1,"ok":true,"value":{"accepted":true,"command":"create-profile"}}'
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command create-profile --es network android-e2e --es bootstrap_peer_id '*)
                    : "''${pairing_state:?}"
                    printf 'profile\n' > "$pairing_state"
                    response='{"schema_version":1,"ok":true,"value":{"accepted":true,"command":"create-profile"}}'
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell appops set org.hermeticfoundation.p2pvpn.debug ACTIVATE_VPN allow') ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command connect')
                    if [[ -n "$pairing_state" ]]; then
                      printf 'connected\n' > "$pairing_state"
                    else
                      : "''${always_on_state:?}"
                      printf 'manual\n' > "$always_on_state"
                    fi
                    response='{"schema_version":1,"ok":true,"value":{"accepted":true,"command":"connect"}}'
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command disconnect')
                    response='{"schema_version":1,"ok":true,"value":{"accepted":true,"command":"disconnect"}}'
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell settings put secure always_on_vpn_app org.hermeticfoundation.p2pvpn.debug')
                    : "''${always_on_state:?}"
                    printf 'always-on\n' > "$always_on_state"
                    ;;
                  'shell settings put secure always_on_vpn_lockdown 1')
                    : "''${always_on_state:?}"
                    printf 'lockdown\n' > "$always_on_state"
                    ;;
                  'shell settings put secure always_on_vpn_lockdown 0')
                    if [[ -n "$always_on_state" && -s "$always_on_state" \
                      && "$(< "$always_on_state")" == lockdown ]]; then
                      printf 'restored\n' > "$always_on_state"
                    fi
                    ;;
                  'shell settings delete secure always_on_vpn_app')
                    if [[ -n "$always_on_state" ]]; then
                      printf 'manual\n' > "$always_on_state"
                    fi
                    ;;
                  'shell am broadcast --receiver-foreground -a org.hermeticfoundation.p2pvpn.debug.AUTOMATION -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.DebugAutomationReceiver --es command join-pairing --es code '*)
                    : "''${pairing_state:?}"
                    if [[ ! -s "$pairing_state.runtime-phase" \
                      || "$(< "$pairing_state.runtime-phase")" != running ]]; then
                      echo 'pairing was requested before the selected network was running' >&2
                      exit 2
                    fi
                    printf 'paired\n' > "$pairing_state"
                    response='{"schema_version":1,"ok":true,"value":{"accepted":true,"command":"join-pairing"}}'
                    printf 'Broadcast completed: result=-1, data="%s"\n' "$(printf '%s' "$response" | base64 -w 0)"
                    ;;
                  'shell pidof org.hermeticfoundation.p2pvpn.debug')
                    if [[ -n "$always_on_state" && -s "$always_on_state" \
                      && "$(< "$always_on_state")" == updated ]]; then
                      printf '5252\n'
                    else
                      printf '4242\n'
                    fi
                    ;;
                  logcat*)
                    printf '1.0 I p2p-vpn: p2p_vpn::runtime::runner event=test peer=12D3KooWFakeAndroidPeer legacy-peer=QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN overlay=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef address=/ip6/fd42::9/tcp/42300 key=/members/c2VjcmV0+/membership-records/1\n'
                    ;;
                  'shell svc wifi disable')
                    : "''${underlay_state:?}"
                    printf 'cellular\n' > "$underlay_state"
                    ;;
                  'shell svc data disable')
                    : "''${underlay_state:?}"
                    [[ "$(< "$underlay_state")" == cellular ]]
                    printf 'none\n' > "$underlay_state"
                    ;;
                  'shell svc data enable')
                    : "''${underlay_state:?}"
                    [[ "$(< "$underlay_state")" == none ]]
                    printf 'recovered-cellular\n' > "$underlay_state"
                    ;;
                  'shell svc wifi enable')
                    : "''${underlay_state:?}"
                    [[ "$(< "$underlay_state")" == recovered-cellular ]]
                    printf 'restored-wifi\n' > "$underlay_state"
                    ;;
                  shell\ ping\ -c\ 5\ -W\ 5\ *)
                    record_fake_traffic 5
                    for sequence in 1 2 3 4 5; do
                      printf '64 bytes from 100.64.0.9: icmp_seq=%s ttl=64 time=1.0 ms\n' "$sequence"
                    done
                    printf '5 packets transmitted, 5 packets received, 0%% packet loss\n'
                    ;;
                  shell\ ping6\ -c\ 5\ -W\ 5\ *)
                    record_fake_traffic 5
                    for sequence in 1 2 3 4 5; do
                      printf '64 bytes from fd42::9: icmp_seq=%s ttl=64 time=1.0 ms\n' "$sequence"
                    done
                    printf '5 packets transmitted, 5 packets received, 0%% packet loss\n'
                    ;;
                  shell\ ping\ -c\ 1\ -W\ 2\ *)
                    record_fake_traffic 1
                    printf '1 packet transmitted, 1 packet received, 0%% packet loss\n'
                    ;;
                  shell\ ping6\ -c\ 1\ -W\ 2\ *)
                    record_fake_traffic 1
                    printf '1 packet transmitted, 1 packet received, 0%% packet loss\n'
                    ;;
                  'shell am force-stop org.hermeticfoundation.p2pvpn.debug') ;;
                  'shell am start -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.MainActivity' | \
                    'shell am start -W -n org.hermeticfoundation.p2pvpn.debug/org.hermeticfoundation.p2pvpn.MainActivity')
                    printf 'Starting: Intent\n'
                    ;;
                  install\ -r\ *)
                    if [[ -n "$always_on_state" && -s "$always_on_state" \
                      && "$(< "$always_on_state")" == always-on ]]; then
                      printf 'updated\n' > "$always_on_state"
                    fi
                    printf 'Success\n'
                    ;;
                  *) printf 'unexpected fake ADB call: %s\n' "$*" >&2; exit 2 ;;
                esac
                EOF
                chmod +x "$test_root/bin/fake-adb"

                assert_diagnostic_evidence() {
                  local evidence="$1"
                  local expected_connected="$2"
                  local diagnostic_size
                  jq -e --argjson expected_connected "$expected_connected" '
                    .cleanup.diagnostic_report_redacted and
                    all(.steps[]; (.recorded_unix_millis | type == "number")) and
                    all(.steps[] | select(.measurement.reply_sequences? != null);
                      .measurement.reply_sequences == [1, 2, 3, 4, 5] and
                      .measurement.finished_unix_millis >= .measurement.started_unix_millis) and
                    .device.diagnostics.os_underlay == {
                      status: "parsed",
                      networks: [
                        {kind: "wifi", validated: true, internet: true, not_vpn: true},
                        {kind: "cellular", validated: false, internet: true, not_vpn: true},
                        {kind: "vpn", validated: true, internet: true, not_vpn: false},
                        {kind: "vpn", validated: false, internet: true, not_vpn: false}
                      ]
                    } and
                    (.device.diagnostics.export |
                      .schema_version == 1 and
                      .kind == "p2p-vpn-android-diagnostics" and
                      .app.android_api == 35 and
                      .lifecycle.connected == $expected_connected and
                      .traffic == {
                        inbound_accepted_packets: 0,
                        outbound_owned_quic_datagram_packets: 0,
                        outbound_sent_packets: 0,
                        tun_read_packets: 0,
                        tun_write_packets: 0
                      } and
                      (.events.items | length <= 64) and
                      .privacy == {
                        identity_material: "excluded",
                        peers: "excluded",
                        pairing_secrets: "excluded",
                        underlay_addresses: "excluded"
                      })
                  ' "$evidence" >/dev/null
                  diagnostic_size="$(jq -c '.device.diagnostics.export' "$evidence" | wc -c)"
                  test "$diagnostic_size" -le ${toString (64 * 1024)}
                  ! jq -c '.device.diagnostics.export' "$evidence" | grep -Eq \
                    '12D3KooW[A-Za-z0-9]+|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef|ABCD-EFGH-JKLM-NPQR|100\.64\.0\.9|fd42::9'
                }

                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario boot-smoke \
                    --output "$test_root/evidence"
                harness_status=$?
                set -e

                if [[ "$harness_status" -ne 0 ]]; then
                  jq . "$test_root/evidence/evidence.json" >&2
                  exit "$harness_status"
                fi
                jq -e '
                  .schema_version == 1 and
                  .kind == "p2p-vpn-android-e2e" and
                  .scenario == "boot-smoke" and
                  .status == "passed" and
                  .device.api_level == "35" and
                  .device.abi == "x86_64" and
                  .device.debug_automation and
                  (.preflight[] | select(.name == "disk_space") | .available == true) and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/evidence/evidence.json" >/dev/null
                assert_diagnostic_evidence "$test_root/evidence/evidence.json" false
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"
                test "$(wc -c < "$test_root/evidence/emulator.log")" -le ${toString (1024 * 1024)}
                ! grep -Fq 'Sending adb public key' "$test_root/evidence/emulator.log"
                ! grep -Fq 'test-user' "$test_root/evidence/emulator.log"
                grep -Fq '/tmp/android-REDACTED/crash.db' "$test_root/evidence/emulator.log"

                adb_timeout_started="$(date +%s)"
                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_FAKE_ADB_HANG=logcat \
                  P2P_VPN_ANDROID_E2E_ADB_TIMEOUT_SECONDS=2 \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario boot-smoke \
                    --output "$test_root/adb-timeout-evidence"
                adb_timeout_status=$?
                set -e
                adb_timeout_elapsed=$(($(date +%s) - adb_timeout_started))

                test "$adb_timeout_status" -eq 0
                test "$adb_timeout_elapsed" -le 15
                jq -e '
                  .status == "passed" and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/adb-timeout-evidence/evidence.json" >/dev/null
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"

                rm -f "$test_root/runtime-storage-trigger"
                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=0 \
                  P2P_VPN_ANDROID_E2E_MAX_RUNTIME_GROWTH_BYTES=1048576 \
                  P2P_VPN_ANDROID_E2E_DF="$test_root/bin/fake-runtime-df" \
                  P2P_VPN_ANDROID_E2E_FAKE_STORAGE_TRIGGER="$test_root/runtime-storage-trigger" \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario boot-smoke \
                    --output "$test_root/runtime-budget-evidence"
                runtime_budget_status=$?
                set -e

                test "$runtime_budget_status" -eq 75
                jq -e '
                  .status == "failed" and
                  .detail == "Android E2E stopped because runtime storage growth exceeded the per-run limit" and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/runtime-budget-evidence/evidence.json" >/dev/null
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"

                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE="$test_root/fake-profile" \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario profile-persistence \
                    --output "$test_root/persistence-evidence"
                persistence_status=$?
                set -e

                if [[ "$persistence_status" -ne 0 ]]; then
                  jq . "$test_root/persistence-evidence/evidence.json" >&2
                  exit "$persistence_status"
                fi
                jq -e '
                  .scenario == "profile-persistence" and
                  .status == "passed" and
                  ([.steps[] | select(.name == "selected_apk" and .status == "passed")] | length == 1) and
                  (([.steps[].name] | index("selected_apk")) < ([.steps[].name] | index("profile_creation"))) and
                  .device.profile_persistence.process_death and
                  .device.profile_persistence.update_install and
                  .device.profile_persistence.replacement_reinstall and
                  .device.profile_persistence.ipv4 and
                  .device.profile_persistence.ipv6 and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/persistence-evidence/evidence.json" >/dev/null
                assert_diagnostic_evidence "$test_root/persistence-evidence/evidence.json" false
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"

                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_FAKE_PROFILE_STATE="$test_root/fake-always-on-profile" \
                  P2P_VPN_ANDROID_E2E_FAKE_ALWAYS_ON_STATE="$test_root/fake-always-on-mode" \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario always-on \
                    --output "$test_root/always-on-evidence"
                always_on_status=$?
                set -e

                if [[ "$always_on_status" -ne 0 ]]; then
                  jq . "$test_root/always-on-evidence/evidence.json" >&2
                  exit "$always_on_status"
                fi
                jq -e '
                  .scenario == "always-on" and
                  .status == "passed" and
                  .device.always_on.manual_connect and
                  .device.always_on.disconnect_guard and
                  .device.always_on.update_restart and
                  .device.always_on.lockdown_guard and
                  .device.always_on.lockdown_recovery and
                  .device.always_on.profile_identity_preserved and
                  .cleanup.always_on_cleared and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/always-on-evidence/evidence.json" >/dev/null
                assert_diagnostic_evidence "$test_root/always-on-evidence/evidence.json" true
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"

                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_FAKE_PAIRING_STATE="$test_root/fake-pairing" \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                  P2P_VPN_ANDROID_E2E_FIXTURE="$test_root/bin/fake-fixture" \
                  P2P_VPN_BIN="$test_root/bin/fake-p2p-vpn" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario pairing-traffic \
                    --output "$test_root/pairing-evidence"
                pairing_status=$?
                set -e

                if [[ "$pairing_status" -ne 0 ]]; then
                  jq . "$test_root/pairing-evidence/evidence.json" >&2
                  cat "$test_root/pairing-evidence/fixture.log" >&2
                  exit "$pairing_status"
                fi
                jq -e '
                  .scenario == "pairing-traffic" and
                  .status == "passed" and
                  .device.pairing_traffic.code_only_enrollment and
                  .device.pairing_traffic.configured_overlay_peer_addresses == 0 and
                  .device.pairing_traffic.path_mode == "automatic" and
                  .device.pairing_traffic.readiness_attempts.linux_to_android_ipv4 == 1 and
                  .device.pairing_traffic.readiness_attempts.linux_to_android_ipv6 == 1 and
                  .device.pairing_traffic.readiness_attempts.android_to_linux_ipv4 == 1 and
                  .device.pairing_traffic.readiness_attempts.android_to_linux_ipv6 == 1 and
                  .device.pairing_traffic.linux_to_android.ipv4.received == 5 and
                  .device.pairing_traffic.linux_to_android.ipv6.received == 5 and
                  .device.pairing_traffic.android_to_linux.ipv4.received == 5 and
                  .device.pairing_traffic.android_to_linux.ipv6.received == 5 and
                  .device.pairing_traffic.paths.direct_tcp_stream == 1 and
                  .cleanup.emulator_stopped and
                  .cleanup.fixture_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/pairing-evidence/evidence.json" >/dev/null
                assert_diagnostic_evidence "$test_root/pairing-evidence/evidence.json" true
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"
                test "$(wc -c < "$test_root/pairing-evidence/fixture.log")" -le ${toString (1024 * 1024)}
                ! grep -Fq 'ABCD-EFGH-JKLM-NPQR' "$test_root/pairing-evidence/fixture.log"
                ! grep -Fq "$test_root/tmp/p2p-vpn-android-e2e-state." \
                  "$test_root/pairing-evidence/fixture.log"
                ! grep -Eq '(secret-tag|secret-key|secret-signature|certificate_der: Some)' \
                  "$test_root/pairing-evidence/fixture.log"
                ! grep -Eq '(192\.0\.2\.44|fd00::44|private\.example)' \
                  "$test_root/pairing-evidence/fixture.log"
                ! grep -Eq 'Qm[1-9A-HJ-NP-Za-km-z]{44}|12D3KooW[A-Za-z0-9]+' \
                  "$test_root/pairing-evidence/fixture.log"
                ! grep -Fq '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
                  "$test_root/pairing-evidence/fixture.log"
                ! grep -Fq 'c2VjcmV0+' "$test_root/pairing-evidence/fixture.log"
                grep -Fq 'peer PEER-ID-REDACTED' \
                  "$test_root/pairing-evidence/fixture.log"
                grep -Fq 'legacy-peer=PEER-ID-REDACTED' \
                  "$test_root/pairing-evidence/fixture.log"
                grep -Fq 'overlay=OVERLAY-ID-REDACTED' \
                  "$test_root/pairing-evidence/fixture.log"
                grep -Fq '/members/MEMBERSHIP-TAG-REDACTED/membership-records/1' \
                  "$test_root/pairing-evidence/fixture.log"
                test "$(wc -c < "$test_root/pairing-evidence/android.log")" -le ${toString (1024 * 1024)}
                ! grep -Eq 'Qm[1-9A-HJ-NP-Za-km-z]{44}|12D3KooW[A-Za-z0-9]+|fd42::9|c2VjcmV0+|0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' \
                  "$test_root/pairing-evidence/android.log"
                grep -Fq 'p2p_vpn::runtime::runner' \
                  "$test_root/pairing-evidence/android.log"
                grep -Fq 'peer=PEER-ID-REDACTED' \
                  "$test_root/pairing-evidence/android.log"
                grep -Fq 'legacy-peer=PEER-ID-REDACTED' \
                  "$test_root/pairing-evidence/android.log"
                grep -Fq 'overlay=OVERLAY-ID-REDACTED' \
                  "$test_root/pairing-evidence/android.log"

                underlay_pairing_state="$test_root/fake-pairing-underlay"
                underlay_traffic_state="$test_root/fake-traffic-underlay"
                underlay_state="$test_root/fake-underlay"
                printf '0\n' > "$underlay_traffic_state"
                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_FAKE_PAIRING_STATE="$underlay_pairing_state" \
                  P2P_VPN_ANDROID_E2E_FAKE_TRAFFIC_STATE="$underlay_traffic_state" \
                  P2P_VPN_ANDROID_E2E_FAKE_UNDERLAY_STATE="$underlay_state" \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                  P2P_VPN_ANDROID_E2E_FIXTURE="$test_root/bin/fake-fixture" \
                  P2P_VPN_BIN="$test_root/bin/fake-p2p-vpn" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario underlay-recovery \
                    --output "$test_root/underlay-evidence"
                underlay_status=$?
                set -e

                if [[ "$underlay_status" -ne 0 ]]; then
                  jq . "$test_root/underlay-evidence/evidence.json" >&2
                  exit "$underlay_status"
                fi
                jq -e '
                  .scenario == "underlay-recovery" and
                  .status == "passed" and
                  .device.pairing_traffic.code_only_enrollment and
                  .device.pairing_traffic.configured_overlay_peer_addresses == 0 and
                  .device.pairing_traffic.path_mode == "automatic" and
                  .device.underlay_recovery.underlays == {
                    initial: "wifi",
                    fallback: "cellular",
                    outage: "none",
                    recovered: "cellular",
                    restored: "wifi"
                  } and
                  (.device.underlay_recovery.events.selection_changes_after -
                    .device.underlay_recovery.events.selection_changes_before) >= 4 and
                  (.device.underlay_recovery.events.selected_losses_after -
                    .device.underlay_recovery.events.selected_losses_before) >= 2 and
                  (.device.underlay_recovery.events.recoveries_after -
                    .device.underlay_recovery.events.recoveries_before) >= 1 and
                  (.device.underlay_recovery.events.runtime_recovery_requests_after -
                    .device.underlay_recovery.events.runtime_recovery_requests_before) >= 4 and
                  (.device.underlay_recovery.events.runtime_recovery_failures_after -
                    .device.underlay_recovery.events.runtime_recovery_failures_before) == 0 and
                  .device.underlay_recovery.timing_millis.outage_hold == 5000 and
                  (.device.underlay_recovery.continuity.runtime_restarted | not) and
                  .device.underlay_recovery.continuity.android_process_continuous and
                  .device.underlay_recovery.continuity.fixture_process_continuous and
                  .device.underlay_recovery.traffic.cellular_fallback.linux_to_android.ipv4.received == 5 and
                  .device.underlay_recovery.traffic.cellular_fallback.android_to_linux.ipv6.received == 5 and
                  .device.underlay_recovery.traffic.cellular_recovery.linux_to_android.ipv6.received == 5 and
                  .device.underlay_recovery.traffic.cellular_recovery.android_to_linux.ipv4.received == 5 and
                  .device.underlay_recovery.traffic.wifi_restore.linux_to_android.ipv4.received == 5 and
                  .device.underlay_recovery.traffic.wifi_restore.android_to_linux.ipv6.received == 5 and
                  .cleanup.emulator_stopped and
                  .cleanup.fixture_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/underlay-evidence/evidence.json" >/dev/null
                assert_diagnostic_evidence "$test_root/underlay-evidence/evidence.json" true
                jq -e '.device.diagnostics.export.underlay.kind == "wifi"' \
                  "$test_root/underlay-evidence/evidence.json" >/dev/null
                test "$(< "$underlay_state")" = restored-wifi
                test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"

                for path_mode in quic-stream tcp-stream owned-quic relay-only relay-to-direct; do
                  path_state="$test_root/fake-pairing-$path_mode"
                  path_traffic_state="$test_root/fake-traffic-$path_mode"
                  path_promotion_state="$test_root/fake-promotion-$path_mode"
                  path_evidence="$test_root/path-$path_mode-evidence"
                  printf '0\n' > "$path_traffic_state"
                  set +e
                  TMPDIR="$test_root/tmp" \
                    P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                    P2P_VPN_ANDROID_E2E_FAKE_PAIRING_STATE="$path_state" \
                    P2P_VPN_ANDROID_E2E_FAKE_PATH_MODE="$path_mode" \
                    P2P_VPN_ANDROID_E2E_FAKE_TRAFFIC_STATE="$path_traffic_state" \
                    P2P_VPN_ANDROID_E2E_FAKE_PROMOTION_STATE="$path_promotion_state" \
                    P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                    P2P_VPN_ADB="$test_root/bin/fake-adb" \
                    P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                    P2P_VPN_ANDROID_E2E_FIXTURE="$test_root/bin/fake-fixture" \
                    P2P_VPN_BIN="$test_root/bin/fake-p2p-vpn" \
                    bash ${./scripts/android-e2e.sh} \
                      --scenario pairing-traffic \
                      --path-mode "$path_mode" \
                      --output "$path_evidence"
                  path_status=$?
                  set -e

                  if [[ "$path_status" -ne 0 ]]; then
                    jq . "$path_evidence/evidence.json" >&2
                    exit "$path_status"
                  fi
                  jq -e --arg path_mode "$path_mode" '
                    .status == "passed" and
                    .device.pairing_traffic.path_mode == $path_mode and
                    (if $path_mode == "quic-stream" then
                      .device.pairing_traffic.paths.direct_quic_stream == 1 and
                      .device.pairing_traffic.paths.direct_tcp_stream == 0
                    elif $path_mode == "tcp-stream" then
                      .device.pairing_traffic.paths.direct_quic_stream == 0 and
                      .device.pairing_traffic.paths.direct_tcp_stream == 1
                    elif $path_mode == "owned-quic" then
                      .device.pairing_traffic.paths.direct_quic_datagram == 1 and
                      .device.pairing_traffic.paths.packet_plane_quic_sessions == 1 and
                      .device.pairing_traffic.owned_quic.measured_packet_delta >= 20
                    elif $path_mode == "relay-only" then
                      .device.pairing_traffic.paths.relay == 1 and
                      .device.pairing_traffic.paths.direct_quic_stream == 0 and
                      .device.pairing_traffic.paths.direct_tcp_stream == 0 and
                      .device.pairing_traffic.relay_only.selected_circuit_paths >= 1 and
                      .device.pairing_traffic.relay_only.outbound_stream_packets >= 20 and
                      .device.pairing_traffic.relay_only.established_circuits >= 1
                    else
                      .device.pairing_traffic.paths.direct_tcp_stream == 1 and
                      .device.pairing_traffic.paths.promotions_to_direct >= 1 and
                      .device.pairing_traffic.relay_to_direct.initial_path == "circuit_relay" and
                      .device.pairing_traffic.relay_to_direct.promoted_path == "tcp_stream" and
                      (.device.pairing_traffic.relay_to_direct.runtime_restarted | not) and
                      .device.pairing_traffic.relay_to_direct.fixture_process_continuous and
                      .device.pairing_traffic.relay_to_direct.measured_relay_packet_delta >= 20 and
                      .device.pairing_traffic.relay_to_direct.linux_measured_direct_packet_delta >= 20 and
                      .device.pairing_traffic.relay_to_direct.android_measured_direct_packet_delta >= 20 and
                      .device.pairing_traffic.relay_to_direct.promoted_linux_to_android.ipv4.received == 5 and
                      .device.pairing_traffic.relay_to_direct.promoted_linux_to_android.ipv6.received == 5 and
                      .device.pairing_traffic.relay_to_direct.promoted_android_to_linux.ipv4.received == 5 and
                      .device.pairing_traffic.relay_to_direct.promoted_android_to_linux.ipv6.received == 5
                    end) and
                    .cleanup.emulator_stopped and
                    .cleanup.fixture_stopped and
                    .cleanup.private_state_removed and
                    .cleanup.logs_redacted
                  ' "$path_evidence/evidence.json" >/dev/null
                  assert_diagnostic_evidence "$path_evidence/evidence.json" true
                  test -z "$(find "$test_root/tmp" -maxdepth 1 -name 'p2p-vpn-android-e2e-state.*' -print -quit)"
                done

                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  P2P_VPN_ANDROID_APK="$test_root/fake.apk" \
                  P2P_VPN_ANDROID_E2E_FIXTURE="$test_root/bin/fake-fixture" \
                  P2P_VPN_BIN="$test_root/bin/fake-p2p-vpn" \
                  bash ${./scripts/android-e2e.sh} \
                    --scenario multi-network \
                    --preflight \
                    --output "$test_root/multi-network-preflight"
                jq -e '
                  .scenario == "multi-network" and
                  .status == "passed" and
                  (.preflight[] | select(.name == "fixture_command") | .available) and
                  (.preflight[] | select(.name == "p2p_vpn_command") | .available) and
                  .cleanup.fixture_stopped and
                  .cleanup.logs_redacted and
                  .artifacts.fixture_secondary_log == "fixture-secondary.log"
                ' "$test_root/multi-network-preflight/evidence.json" >/dev/null

                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/missing-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  bash ${./scripts/android-e2e.sh} \
                    --preflight \
                    --output "$test_root/skip-evidence"
                skip_status=$?
                set -e

                test "$skip_status" -eq 77
                jq -e '
                  .status == "skipped" and
                  .detail == "Missing requirements: emulator_command" and
                  (.preflight[] | select(.name == "emulator_command") | .available == false) and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/skip-evidence/evidence.json" >/dev/null
                test ! -s "$test_root/skip-evidence/emulator.log"

                mkdir -p "$test_root/space-evidence"
                set +e
                TMPDIR="$test_root/tmp" \
                  P2P_VPN_ANDROID_E2E_TEST_MODE=1 \
                  P2P_VPN_ANDROID_E2E_MIN_FREE_BYTES=900000000000000000 \
                  P2P_VPN_ANDROID_EMULATOR="$test_root/bin/fake-emulator" \
                  P2P_VPN_ADB="$test_root/bin/fake-adb" \
                  bash ${./scripts/android-e2e.sh} \
                    --preflight \
                    --output "$test_root/space-evidence"
                space_status=$?
                set -e

                test "$space_status" -eq 77
                jq -e '
                  .status == "skipped" and
                  .detail == "Missing requirements: disk_space" and
                  (.preflight[] | select(.name == "disk_space") | .available == false) and
                  .cleanup.emulator_stopped and
                  .cleanup.private_state_removed and
                  .cleanup.logs_redacted
                ' "$test_root/space-evidence/evidence.json" >/dev/null
                test ! -s "$test_root/space-evidence/emulator.log"

                touch "$out"
              ''
          else
            null;
        androidDeviceAuditStructure =
          if androidSupported then
            pkgs.runCommand "p2p-vpn-android-device-audit-structure"
              {
                nativeBuildInputs = [
                  pkgs.bash
                  pkgs.coreutils
                  pkgs.gawk
                  pkgs.gnugrep
                  pkgs.gnused
                  pkgs.jq
                  (lib.getBin pkgs.shellcheck)
                ];
              }
              ''
                shellcheck ${./scripts/android-device-audit.sh}
                shellcheck ${./tests/android-device-audit/fake-adb.sh}
                shellcheck ${./tests/android-device-audit/fake-ping.sh}

                test_root="$TMPDIR/android-device-audit-test"
                mkdir -p \
                  "$test_root/bin" \
                  "$test_root/tmp" \
                  "$test_root/preflight-state" \
                  "$test_root/full-state" \
                  "$test_root/full-evidence" \
                  "$test_root/core-state" \
                  "$test_root/core-evidence" \
                  "$test_root/delayed-profile-state" \
                  "$test_root/delayed-profile-evidence" \
                  "$test_root/upstream-vpn-state" \
                  "$test_root/upstream-vpn-evidence" \
                  "$test_root/failure-state" \
                  "$test_root/failure-evidence"
                printf 'apk\n' > "$test_root/fake.apk"
                cp ${./tests/android-device-audit/fake-adb.sh} "$test_root/bin/fake-adb"
                cp ${./tests/android-device-audit/fake-ping.sh} "$test_root/bin/fake-ping"
                chmod +x "$test_root/bin/fake-adb" "$test_root/bin/fake-ping"
                patchShebangs "$test_root/bin"

                common_environment=(
                  P2P_VPN_ADB="$test_root/bin/fake-adb"
                  P2P_VPN_ANDROID_DEVICE_AUDIT_PING="$test_root/bin/fake-ping"
                  P2P_VPN_ANDROID_DEVICE_AUDIT_AUTO_CONFIRM=1
                  P2P_VPN_ANDROID_DEVICE_AUDIT_MIN_FREE_BYTES=0
                  TMPDIR="$test_root/tmp"
                )

                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --apk "$test_root/fake.apk" \
                    --preflight
                ! grep -Fq ' install ' "$test_root/preflight-state/adb.log"

                for api in 26 28 29; do
                  set +e
                  env \
                    "''${common_environment[@]}" \
                    P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                    P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_API="$api" \
                    bash ${./scripts/android-device-audit.sh} \
                      --apk "$test_root/fake.apk" \
                      --preflight
                  sdk_status=$?
                  set -e
                  if ((api < 29)); then
                    test "$sdk_status" -eq 2
                  else
                    test "$sdk_status" -eq 0
                  fi
                  ! grep -Fq ' install ' "$test_root/preflight-state/adb.log"
                done

                set +e
                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_MODE=wrong-abi \
                  bash ${./scripts/android-device-audit.sh} \
                    --apk "$test_root/fake.apk" \
                    --preflight
                wrong_abi_status=$?
                set -e
                test "$wrong_abi_status" -eq 2

                set +e
                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/unattended-evidence" \
                    --apk "$test_root/fake.apk"
                unattended_status=$?
                set -e
                test "$unattended_status" -eq 2
                ! grep -Fq ' install ' "$test_root/preflight-state/adb.log"

                set +e
                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --network physical-test \
                    --peer-ipv4 '100.64.0.1;id' \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/rejected-evidence" \
                    --apk "$test_root/fake.apk" \
                    --duration-seconds 1 \
                    --doze-seconds 1 \
                    --allow-short
                unsafe_address_status=$?
                set -e
                test "$unsafe_address_status" -eq 2
                ! grep -Fq ' install ' "$test_root/preflight-state/adb.log"

                set +e
                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/preflight-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --scenario unsupported \
                    --apk "$test_root/fake.apk" \
                    --preflight
                unsupported_scenario_status=$?
                set -e
                test "$unsupported_scenario_status" -eq 2
                ! grep -Fq ' install ' "$test_root/preflight-state/adb.log"

                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/full-state" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_MODE=fresh-pair \
                  bash ${./scripts/android-device-audit.sh} \
                    --pair \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/full-evidence" \
                    --apk "$test_root/fake.apk" \
                    --duration-seconds 1 \
                    --sample-seconds 1 \
                    --doze-seconds 1 \
                    --transition-timeout 10 \
                    --allow-short

                jq -e '
                  .schema_version == 1 and
                  .kind == "p2p-vpn-android-physical-audit" and
                  .outcome == "passed" and
                  .contract.scenario == "full" and
                  .contract.minimum_api == 29 and
                  (.contract.coverage | to_entries | all(.value)) and
                  (.contract.proof_eligible | not) and
                  .contract.operator.automatic_confirmation and
                  .contract.operator.interactive_transition_confirmations == 0 and
                  .contract.operator.required_transition_confirmations == 3 and
                  .device.abi == "arm64-v8a" and
                  .device.android_api == 35 and
                  .device.serial == "excluded" and
                  .device.model == "excluded" and
                  .pairing.performed_during_run and
                  .management_path.adb_only and
                  (.management_path.adb_forward | not) and
                  (.management_path.adb_reverse | not) and
                  [.steps[].name] == [
                    "pairing",
                    "lan_baseline",
                    "hotspot_or_cellular",
                    "hotspot_upstream_vpn",
                    "lan_return",
                    "screen_off_doze",
                    "sustained_connection",
                    "process_service_recreation",
                    "in_place_apk_update"
                  ] and
                  ([.steps[].state] | all(. == "passed")) and
                  ([.steps[] | select(.name == "hotspot_or_cellular" or
                    .name == "hotspot_upstream_vpn" or .name == "lan_return") |
                    .data.operator_confirmed] | all(. == false)) and
                  (.steps[] | select(.name == "screen_off_doze") |
                    .data.deep_idle_observed) and
                  .sustained.sent >= 20 and
                  .sustained.received == .sustained.sent and
                  .sustained.packet_loss_basis_points == 0 and
                  .sustained.battery.unplugged_measurement and
                  .final_diagnostics.privacy.identity_material == "excluded" and
                  .privacy.peer_ids == "excluded" and
                  .privacy.overlay_addresses == "excluded" and
                  .privacy.pairing_codes == "excluded" and
                  .cleanup.doze_released and
                  .cleanup.screen_awake and
                  .cleanup.private_state_removed and
                  .cleanup.profile_preserved
                ' "$test_root/full-evidence/evidence.json" >/dev/null
                test "$(wc -c < "$test_root/full-evidence/evidence.json")" -le 2097152
                ! grep -Eq \
                  '12D3KooWFakeAndroidPeer|100\.64\.0\.9|fd42::9|TEST-PAIRING-CODE' \
                  "$test_root/full-evidence/evidence.json"
                ! grep -Eq '(^|[[:space:]])(forward|reverse)([[:space:]]|$)' \
                  "$test_root/full-state/adb.log"
                test "$(grep -c ' install -r ' "$test_root/full-state/adb.log")" -eq 2

                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/core-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --scenario core \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/core-evidence" \
                    --apk "$test_root/fake.apk" \
                    --duration-seconds 1 \
                    --sample-seconds 1 \
                    --doze-seconds 1 \
                    --transition-timeout 10 \
                    --allow-short

                jq -e '
                  .outcome == "passed" and
                  .contract.scenario == "core" and
                  .contract.coverage == {
                    cellular_or_hotspot: true,
                    upstream_vpn: false,
                    lan_return: true,
                    doze: true,
                    sustained: true,
                    process_recreation: true,
                    in_place_update: true
                  } and
                  .contract.operator.required_transition_confirmations == 2 and
                  [.steps[].name] == [
                    "lan_baseline",
                    "hotspot_or_cellular",
                    "lan_return",
                    "screen_off_doze",
                    "sustained_connection",
                    "process_service_recreation",
                    "in_place_apk_update"
                  ] and
                  ([.steps[].state] | all(. == "passed")) and
                  .sustained.sent >= 20
                ' "$test_root/core-evidence/evidence.json" >/dev/null
                test "$(grep -c ' install -r ' "$test_root/core-state/adb.log")" -eq 2

                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/delayed-profile-state" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_MODE=delayed-profile \
                  bash ${./scripts/android-device-audit.sh} \
                    --scenario core \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/delayed-profile-evidence" \
                    --apk "$test_root/fake.apk" \
                    --duration-seconds 1 \
                    --sample-seconds 1 \
                    --doze-seconds 1 \
                    --transition-timeout 10 \
                    --allow-short

                jq -e '.outcome == "passed"' \
                  "$test_root/delayed-profile-evidence/evidence.json" >/dev/null
                test "$(< "$test_root/delayed-profile-state/status-count")" -ge 3

                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/upstream-vpn-state" \
                  bash ${./scripts/android-device-audit.sh} \
                    --scenario upstream-vpn \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/upstream-vpn-evidence" \
                    --apk "$test_root/fake.apk" \
                    --transition-timeout 10 \
                    --allow-short

                jq -e '
                  .outcome == "passed" and
                  .contract.scenario == "upstream-vpn" and
                  .contract.coverage == {
                    cellular_or_hotspot: false,
                    upstream_vpn: true,
                    lan_return: true,
                    doze: false,
                    sustained: false,
                    process_recreation: false,
                    in_place_update: false
                  } and
                  .contract.operator.required_transition_confirmations == 2 and
                  [.steps[].name] == [
                    "lan_baseline",
                    "hotspot_upstream_vpn",
                    "lan_return"
                  ] and
                  ([.steps[].state] | all(. == "passed")) and
                  .sustained == null
                ' "$test_root/upstream-vpn-evidence/evidence.json" >/dev/null
                test "$(grep -c ' install -r ' "$test_root/upstream-vpn-state/adb.log")" -eq 1
                ! grep -Fq 'shell dumpsys deviceidle force-idle' \
                  "$test_root/upstream-vpn-state/adb.log"

                set +e
                env \
                  "''${common_environment[@]}" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_STATE="$test_root/failure-state" \
                  P2P_VPN_ANDROID_DEVICE_AUDIT_FAKE_MODE=doze-fail \
                  bash ${./scripts/android-device-audit.sh} \
                    --network physical-test \
                    --peer-ipv4 100.64.0.1 \
                    --peer-ipv6 fd42::1 \
                    --output "$test_root/failure-evidence" \
                    --apk "$test_root/fake.apk" \
                    --duration-seconds 1 \
                    --sample-seconds 1 \
                    --doze-seconds 1 \
                    --transition-timeout 10 \
                    --allow-short
                failure_status=$?
                set -e
                test "$failure_status" -eq 1
                jq -e '
                  .outcome == "failed" and
                  .detail == "Android could not enter forced Doze" and
                  .contract.scenario == "full" and
                  (.contract.proof_eligible | not) and
                  .cleanup.doze_released and
                  .cleanup.screen_awake and
                  .cleanup.private_state_removed and
                  .cleanup.profile_preserved
                ' "$test_root/failure-evidence/evidence.json" >/dev/null
                grep -Fq 'shell dumpsys deviceidle unforce' "$test_root/failure-state/adb.log"
                grep -Fq 'shell input keyevent 224' "$test_root/failure-state/adb.log"

                test -z "$(find "$test_root/tmp" -maxdepth 1 \
                  -name 'p2p-vpn-android-device-audit.*' -print -quit)"
                touch "$out"
              ''
          else
            null;
      in
      {
        packages = {
          default = package;
          webrtc = package.overrideAttrs (_: {
            cargoBuildFeatures = [ "webrtc" ];
            cargoCheckFeatures = [ "webrtc" ];
          });
          demand-lifecycle-trial = package.overrideAttrs (_: {
            cargoBuildFeatures = [ "demand-lifecycle-trial" ];
            cargoCheckFeatures = [ "demand-lifecycle-trial" ];
          });
          check-fast = checkFast;
        }
        // lib.optionalAttrs (system == "x86_64-linux") {
          browser-sdk = import ./nix/browser-sdk.nix {
            inherit pkgs;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./Cargo.toml
                ./Cargo.lock
                ./vendor
                ./src
                ./crates/p2p-vpn-android
                ./crates/p2p-vpn-android-e2e-fixture
                ./crates/p2p-vpn-browser/Cargo.toml
                ./crates/p2p-vpn-browser/src
                ./scripts/build-browser-sdk.sh
              ];
            };
            cargoLock.lockFile = ./Cargo.lock;
          };
        }
        // lib.optionalAttrs androidSupported {
          android-battery-decode = androidBatteryDecoder;
          android-cellular-compare = androidCellularCompare;
          android-cellular-capture = androidCellularCapture;
          android-battery-paired = androidBatteryPaired;
          android-native = android.androidNative;
          android-aar = android.androidAar;
          android-aar-demand-lifecycle-trial = androidLifecycleTrial.androidAar;
          android-native-arm64 = android.androidNativeArm64;
          android-native-x86_64 = android.androidNativeX86_64;
          android-rust-tests = android.androidRustTests;
          android-debug-apk = android.androidDebugApk;
          android-native-arm64-demand-lifecycle-trial = androidLifecycleTrial.androidNativeArm64;
          android-native-x86_64-demand-lifecycle-trial = androidLifecycleTrial.androidNativeX86_64;
          android-debug-apk-demand-lifecycle-trial = androidLifecycleTrial.androidDebugApk;
          android-device-audit = androidDeviceAuditLauncher;
          android-device-audit-runtime = androidDeviceAuditRuntime;
          android-e2e-fixture = androidE2eFixture;
          android-e2e-fixture-demand-lifecycle-trial = androidE2eFixture.overrideAttrs (_: {
            cargoBuildFeatures = [ "demand-lifecycle-trial" ];
            cargoCheckFeatures = [ "demand-lifecycle-trial" ];
          });
          android-emulator = android.androidEmulator;
          android-sdk = android.androidSdk;
        };

        apps = {
          check-fast = {
            type = "app";
            program = "${checkFast}/bin/p2p-vpn-check-fast";
            meta = {
              description = "Run formatter, tests, and clippy in the Nix tool environment";
            };
          };
        }
        // lib.optionalAttrs androidSupported {
          android-device-audit = {
            type = "app";
            program = "${androidDeviceAuditLauncher}/bin/p2p-vpn-android-device-audit";
            meta = {
              description = "Safely realize and run the physical arm64 Android audit";
            };
          };
          android-emulator = {
            type = "app";
            program = "${android.androidEmulator}/bin/run-test-emulator";
            meta = {
              description = "Boot a headless emulator and install the p2p-vpn debug APK";
            };
          };
          android-install = {
            type = "app";
            program = "${android.androidInstall}/bin/p2p-vpn-android-install";
            meta = {
              description = "Install the reproducible p2p-vpn Android debug APK";
            };
          };
          android-update-deps = {
            type = "app";
            program = "${android.androidUpdateDeps}/bin/p2p-vpn-android-update-deps";
            meta = {
              description = "Refresh the pinned Android Gradle dependency cache";
            };
          };
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          check-isolated = {
            type = "app";
            program = "${checkIsolated}/bin/p2p-vpn-check-isolated";
            meta = {
              description = "Run offline Rust tests in a quiet loopback-only network namespace";
            };
          };
        };

        checks = {
          package = package;
          demand-lifecycle-trial-packaging =
            let
              packages = self.packages.${system};
              trialFeatures = [ "demand-lifecycle-trial" ];
              androidSeparated =
                !androidSupported
                || (
                  android.androidNativeArm64.cargoBuildFeatures == [ ]
                  && androidLifecycleTrial.androidNativeArm64.cargoBuildFeatures == trialFeatures
                  && lib.hasInfix "--set=build.jobs=$NIX_BUILD_CORES" android.androidNativeArm64.rustCompiler.unwrapped.preConfigure
                  &&
                    android.androidNativeArm64.rustCompiler.outPath
                    == androidLifecycleTrial.androidNativeArm64.rustCompiler.outPath
                  && androidLifecycleTrial.androidRustTests.cargoCheckFeatures == trialFeatures
                  && !(lib.hasInfix "--features demand-lifecycle-trial" android.androidNativeX86_64.buildPhase)
                  && lib.hasInfix "--features demand-lifecycle-trial" androidLifecycleTrial.androidNativeX86_64.buildPhase
                  &&
                    android.androidDebugApk.androidNative.outPath
                    != androidLifecycleTrial.androidDebugApk.androidNative.outPath
                  && packages.android-e2e-fixture.cargoBuildFeatures == [ ]
                  && packages.android-e2e-fixture-demand-lifecycle-trial.cargoBuildFeatures == trialFeatures
                  && packages.android-e2e-fixture-demand-lifecycle-trial.cargoCheckFeatures == trialFeatures
                );
            in
            assert packages.default.cargoBuildFeatures == [ ];
            assert packages.default.cargoCheckFeatures == [ ];
            assert packages.demand-lifecycle-trial.cargoBuildFeatures == trialFeatures;
            assert packages.demand-lifecycle-trial.cargoCheckFeatures == trialFeatures;
            assert androidSeparated;
            pkgs.writeText "p2p-vpn-demand-lifecycle-trial-contract.json" (
              builtins.toJSON {
                default_features = packages.default.cargoBuildFeatures;
                trial_features = trialFeatures;
                android_builds_separated = androidSeparated;
                android_checked = androidSupported;
                validates_runtime_or_energy = false;
              }
            );
          rust-test-sources =
            pkgs.runCommand "p2p-vpn-rust-test-sources"
              {
                nativeBuildInputs = [
                  cargo
                  pkgs.jq
                  pkgs.diffutils
                ];
              }
              ''
                export CARGO_HOME="$TMPDIR/cargo-home"
                rust_targets() {
                  cargo metadata --offline --locked --no-deps --format-version 1 \
                    --manifest-path "$1/Cargo.toml" | jq -S \
                    '[.packages[] | {name, targets: ([.targets[] | {name, kind}] | sort_by(.name, .kind))}] | sort_by(.name)'
                }
                rust_targets ${self} > repository-targets.json
                rust_targets ${rustSource} > packaged-targets.json
                diff -u repository-targets.json packaged-targets.json
                diff -r ${self}/vendor ${rustSource}/vendor
                diff ${self}/docs/developer/protocol/vectors.json \
                  ${rustSource}/docs/developer/protocol/vectors.json
                ${lib.optionalString androidSupported ''
                  diff -r ${self}/vendor ${android.androidNativeArm64.src}/vendor
                  diff -r ${self}/vendor ${android.androidNativeX86_64.src}/vendor
                ''}
                touch "$out"
              '';
          clippy = pkgs.rustPlatform.buildRustPackage {
            pname = "p2p-vpn-clippy";
            version = "0.1.0";
            src = rustSource;
            cargoLock.lockFile = ./Cargo.lock;
            nativeBuildInputs = [
              pkgs.clippy
              pkgs.pkg-config
            ];
            buildPhase = ''
              runHook preBuild
              cargo clippy --jobs "$NIX_BUILD_CORES" --all-targets -- -D clippy::correctness -D clippy::suspicious -D clippy::perf
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              touch $out
              runHook postInstall
            '';
            doCheck = false;
          };
          fmt =
            pkgs.runCommand "p2p-vpn-fmt"
              {
                nativeBuildInputs = [
                  cargo
                  pkgs.rustfmt
                ];
              }
              ''
                cd ${self}
                cargo fmt --check
                touch $out
              '';
        }
        // lib.optionalAttrs androidSupported {
          android-battery-decode = androidBatteryDecoderTests;
          android-cellular-compare = androidCellularCompareTests;
          android-cellular-capture = androidCellularCaptureTests;
          android-battery-paired = androidBatteryPairedTests;
          android = android.androidCheck;
          android-device-audit-structure = androidDeviceAuditStructure;
          android-e2e-fixture = androidE2eFixture;
          android-e2e-structure = androidE2eStructure;
        };

        devShells = {
          default = pkgs.mkShell {
            packages = [
              cargo
              rust
              pkgs.clippy
              pkgs.rustfmt
              pkgs.rust-analyzer
              pkgs.pkg-config
              pkgs.jujutsu
              pkgs.jq
              pkgs.iproute2
              pkgs.iputils
              pkgs.procps
              pkgs.util-linux
            ] ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.glibc.bin ];

            RUST_BACKTRACE = "1";
            RUST_MIN_STACK = "8388608";
          };
        }
        // lib.optionalAttrs androidSupported {
          android = android.androidDevShell;
        };
      }
    );
}
