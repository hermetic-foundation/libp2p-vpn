param([switch]$TestHooks, [switch]$NativeFixture)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
function Invoke-Checked {
    param([string]$Executable, [string[]]$Arguments)
    $ErrorActionPreference = 'Continue'
    & $Executable @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
    if ($LASTEXITCODE -ne 0) { throw "$Executable failed with exit code $LASTEXITCODE" }
}
Push-Location $repo
try {
    Invoke-Checked -Executable rustup -Arguments @('target', 'add', 'wasm32-unknown-unknown')
    $arguments = @('rustc', '--locked', '-p', 'p2p-vpn-browser', '--target', 'wasm32-unknown-unknown', '--lib')
    if ($TestHooks) { $arguments += @('--features', 'test-hooks') }
    # Avoid the Windows LLVM parallel-linker stall; affects build scheduling only.
    $arguments += @('--', '-C', 'link-arg=--threads=1')
    Invoke-Checked -Executable cargo -Arguments $arguments
    $lock = Get-Content -LiteralPath Cargo.lock -Raw
    $version = [regex]::Match($lock, 'name = "wasm-bindgen"\r?\nversion = "([^"]+)"').Groups[1].Value
    if (!$version) { throw 'Cannot determine the locked wasm-bindgen version.' }
    $toolDirectory = Join-Path $repo "target\browser-tools\wasm-bindgen-$version-x86_64-pc-windows-msvc"
    $bindgen = Join-Path $toolDirectory 'wasm-bindgen.exe'
    if (!(Test-Path -LiteralPath $bindgen)) {
        $release = Invoke-RestMethod "https://api.github.com/repos/wasm-bindgen/wasm-bindgen/releases/tags/$version"
        $asset = $release.assets | Where-Object name -eq "wasm-bindgen-$version-x86_64-pc-windows-msvc.tar.gz"
        if (!$asset -or !$asset.digest.StartsWith('sha256:')) { throw 'Published CLI checksum is unavailable.' }
        $toolsDirectory = Join-Path $repo 'target\browser-tools'
        New-Item -ItemType Directory -Path $toolsDirectory -Force | Out-Null
        $archive = Join-Path $toolsDirectory "wasm-bindgen-$version.tar.gz"
        Invoke-WebRequest $asset.browser_download_url -OutFile $archive
        $digest = 'sha256:' + (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -ne $asset.digest) { throw 'wasm-bindgen CLI checksum mismatch.' }
        Invoke-Checked -Executable tar -Arguments @('-xzf', $archive, '-C', $toolsDirectory)
    }
    Invoke-Checked -Executable $bindgen -Arguments @('--target', 'web', '--out-dir', 'crates/p2p-vpn-browser/web/pkg', 'target/wasm32-unknown-unknown/debug/p2p_vpn_browser.wasm')
    if ($NativeFixture) {
        $previousPath = $env:PATH
        $previousFlags = $env:RUSTFLAGS
        try {
            $gnuHost = ((& rustc -vV) -match 'host: x86_64-pc-windows-gnu')
            if ($gnuHost) {
                $env:PATH = (Join-Path (& rustc --print sysroot) 'lib\rustlib\x86_64-pc-windows-gnu\bin\gcc-ld') + ';' + $env:PATH
                $env:RUSTFLAGS = "$previousFlags -C link-arg=-fuse-ld=lld".Trim()
            }
            $nativeArguments = @('rustc', '--locked', '-p', 'p2p-vpn-browser', '--bin', 'browser-fixture', '--', '-C', 'debuginfo=0', '-C', 'strip=debuginfo')
            if ($gnuHost) { $nativeArguments += @('-C', 'link-arg=-Wl,--threads=1') }
            Invoke-Checked -Executable cargo -Arguments $nativeArguments
        } finally { $env:PATH = $previousPath; $env:RUSTFLAGS = $previousFlags }
        Write-Host 'For Windows TUN qualification, place the official signed x64 wintun.dll beside target\debug\browser-fixture.exe.'
    }
    Write-Host 'Built browser WASM package in crates\p2p-vpn-browser\web\pkg'
} finally { Pop-Location }
