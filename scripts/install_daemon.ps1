# Install the broker daemon and seal the pilot package.
# An elevated shell can set NEXUS_PREFIX to C:\ProgramData\nexus-ephemera.
# The default is .\var\nexus-ephemera. The broker secret is not written here.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
if ($env:NEXUS_PREFIX) {
    $Prefix = $env:NEXUS_PREFIX
} else {
    $Prefix = Join-Path $Root "var\nexus-ephemera"
}
New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
Copy-Item (Join-Path $Root "policies\pilot_support_agent.json") (Join-Path $Prefix "pilot_support_agent.json") -Force
$Listen = "\\.\pipe\nexus-ephemera"
@(
    "listen = `"$Listen`""
    "timeout_ms = 5000"
    "policy = `"pilot_support_agent.json`""
    "allow = `"https://api.github.com/repos/pilot-org/support-queue/issues`""
    "redis = `"`""
) | Set-Content -Path (Join-Path $Prefix "config.toml") -Encoding ascii
@(
    "NEXUS_LISTEN=$Listen"
    "NEXUS_POLICY=pilot_support_agent.json"
    "NEXUS_TIMEOUT_MS=5000"
    "NEXUS_REDIS_URL="
) | Set-Content -Path (Join-Path $Prefix ".env") -Encoding ascii
cargo build --manifest-path (Join-Path $Root "Cargo.toml") --release --bin nexus-daemon
$Daemon = Join-Path $Root "target\release\nexus-daemon.exe"
& $Daemon --package $Prefix --seal
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& $Daemon --package $Prefix --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Output "installed $Prefix"
