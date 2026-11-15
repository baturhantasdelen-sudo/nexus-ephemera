param(
    [string]$EvidenceDirectory = (Join-Path $PSScriptRoot '../outputs/enterprise-live')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repository = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$evidence = [System.IO.Path]::GetFullPath($EvidenceDirectory)
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$container = 'nexus-test-' + [Guid]::NewGuid().ToString('N')
$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    $dockerPath = Join-Path $env:ProgramFiles 'Docker/Docker/resources/bin/docker.exe'
} else { $dockerPath = $docker.Source }
$originalLocation = Get-Location
$savedEnvironment = @{}
foreach ($name in @('NEXUS_TEST_REDIS_URL','NEXUS_TEST_RESTART_NAMESPACE','CARGO_INCREMENTAL','RUSTFLAGS')) {
    $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name,'Process')
}
function Invoke-TestGate([string]$LogName, [string[]]$CargoArguments) {
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & cargo @CargoArguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence $LogName)
        $gateExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($gateExit -ne 0) { throw "Test gate failed: $LogName (exit $gateExit)" }
}
function Wait-TestRedis {
    for ($attempt=0; $attempt -lt 30; $attempt++) {
        $reply = & $dockerPath exec $container redis-cli ping 2>$null
        if ($LASTEXITCODE -eq 0 -and $reply -eq 'PONG') { return }
        Start-Sleep -Seconds 1
    }
    throw 'Dedicated test Redis did not become ready'
}
$started = $false
try {
    Set-Location -LiteralPath $repository
    & $dockerPath info --format '{{.ServerVersion}}'
    if ($LASTEXITCODE -ne 0) { throw 'Docker engine access is required; run from your normal PowerShell' }
    & $dockerPath run --detach --rm --name $container --label nexus.enterprise-test=true --memory 256m --cpus 2 --publish '127.0.0.1::6379' redis:7.4 redis-server --appendonly yes --appendfsync always --maxmemory-policy noeviction
    if ($LASTEXITCODE -ne 0) { throw 'Could not start dedicated Redis fixture' }
    $started = $true
    Wait-TestRedis
    $binding = (& $dockerPath port $container '6379/tcp').Trim()
    if ($LASTEXITCODE -ne 0 -or $binding -notmatch '^127\.0\.0\.1:[0-9]+$') { throw 'Unexpected test Redis binding' }
    $env:NEXUS_TEST_REDIS_URL = 'redis://' + $binding
    $env:NEXUS_TEST_RESTART_NAMESPACE = 'restart-' + [Guid]::NewGuid().ToString('N')
    $env:CARGO_INCREMENTAL = '0'
    $env:RUSTFLAGS = '-D warnings'
    & git rev-parse HEAD | Set-Content -LiteralPath (Join-Path $evidence 'commit.txt')
    & git diff --stat | Set-Content -LiteralPath (Join-Path $evidence 'working-tree.txt')
    $sources = Get-ChildItem -LiteralPath @('src','tests','crates','clients/python/src') -Recurse -File |
        Where-Object { $_.Extension -in @('.rs','.toml','.py') }
    @($sources | Get-FileHash -Algorithm SHA256; Get-FileHash -LiteralPath 'Cargo.toml','Cargo.lock' -Algorithm SHA256) |
        ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'source-sha256.json')
    Invoke-TestGate 'redis-claims.log' @('test','--locked','--release','--lib','enterprise_runtime::tests::redis_','--','--ignored','--nocapture')
    Invoke-TestGate 'enterprise-live.log' @('test','--locked','--release','--test','enterprise_live','--','--ignored','--nocapture')
    Invoke-TestGate 'restart-seed.log' @('test','--locked','--release','--lib','enterprise_runtime::tests::restart_seed_committed_receipt','--','--ignored','--exact','--nocapture')
    & $dockerPath restart $container
    if ($LASTEXITCODE -ne 0) { throw 'Real Redis restart failed' }
    Wait-TestRedis
    Invoke-TestGate 'restart-verify.log' @('test','--locked','--release','--lib','enterprise_runtime::tests::restart_verify_committed_receipt','--','--ignored','--exact','--nocapture')
    'PASS: real Redis claims, two live daemons, TLS, crash uncertainty and AOF restart' | Tee-Object -FilePath (Join-Path $evidence 'result.txt')
} finally {
    if ($started) {
        # Only this newly created, randomly named test container is stopped.
        & $dockerPath stop $container | Out-Null
    }
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name,$savedEnvironment[$name],'Process') }
    Set-Location -LiteralPath $originalLocation.Path
}
