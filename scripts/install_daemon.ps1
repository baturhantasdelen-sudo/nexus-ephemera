# Fresh package bootstrap. Rust owns private creation, schema and sealing.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Prefix = if ($env:NEXUS_PREFIX) { $env:NEXUS_PREFIX } else { Join-Path $Root "var\nexus-ephemera" }
cargo build --locked --manifest-path (Join-Path $Root "Cargo.toml") --release --bin nexus-daemon
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$Daemon = Join-Path $Root "target\release\nexus-daemon.exe"
& $Daemon --listen "\\.\pipe\nexus-ephemera" --package $Prefix --init-package
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Daemon --package $Prefix --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "installed $Prefix"
