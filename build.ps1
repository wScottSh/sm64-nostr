#Requires -Version 5.1
<#
.SYNOPSIS
    Single-command build wizard for the sm64-nostr event ROM (Windows / PowerShell).

.DESCRIPTION
    Fire one command; a signed event ROM comes out. The wizard runs the
    interactive parts on the host (baserom preflight, key provisioning) and uses
    Docker only for the actual `make`. See docs/adr/0003-single-command-build-wizard.md.

    The signing key is EPHEMERAL, per-event identity: a fresh 32-byte secp256k1
    secret is minted per build by default and freely overwrites any prior key.
    Paste your own hex to reuse a prior event's key.

.PARAMETER PrivKey
    64-char hex secret to use instead of minting a fresh one (skips the prompt).

.PARAMETER EventName
    REQUIRED human-readable event identity (spec #75, sub-issue #76), shown
    locally in the castle HUD corner -- an event ROM cannot be built without
    one. A-Z, 0-9, and space only (case-folded to upper), 17 chars max;
    gen_event_profile.py validates and rejects (never truncates) inside the
    container. Prompted for interactively if omitted (unless -Yes).

.PARAMETER Clean
    Scratch build (`make clean` first) instead of incremental.

.PARAMETER RebuildImage
    Force `docker build` of the `sm64` image even if it already exists.

.PARAMETER Yes
    Non-interactive: accept every default (fresh-minted key) without prompting.

.EXAMPLE
    .\build.ps1 -EventName "SUMMER JAM 2026"

.EXAMPLE
    .\build.ps1 -Clean -EventName "SUMMER JAM 2026" -PrivKey 77c8613773502387564e091595793df42751daae66dad4475719e4cf70023f2d
#>
[CmdletBinding()]
param(
    [string]$PrivKey,
    [string]$EventName,
    [switch]$Clean,
    [switch]$RebuildImage,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'

# --- constants ---------------------------------------------------------------
$RepoRoot     = $PSScriptRoot
$BaseRom      = Join-Path $RepoRoot 'baserom.us.z64'
$BaseRomSha1  = '9BEF1128717F958171A4AFAC3ED78EE2BB4E86CE'   # Get-FileHash returns upper-case
$KeyDir       = Join-Path $RepoRoot 'keys'
$KeyFile      = Join-Path $KeyDir  'event_privkey.hex'
$ImageName    = 'sm64'
$RomPath      = Join-Path $RepoRoot 'build\us\sm64.us.z64'
$ManifestPath = Join-Path $RepoRoot 'build\us\include\event_profile.manifest.json'
$TotalStages  = 6

# --- UX helpers --------------------------------------------------------------
function Write-Stage {
    param([int]$N, [string]$Title)
    Write-Host ''
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
    Write-Host ("  STAGE $N/$TotalStages  ") -ForegroundColor Cyan -NoNewline
    Write-Host $Title -ForegroundColor White
    Write-Host ("=" * 68) -ForegroundColor DarkCyan
}
function Write-Step { param([string]$Msg) Write-Host "  - $Msg" -ForegroundColor Gray }
function Write-Ok   { param([string]$Msg) Write-Host "  [ok] $Msg" -ForegroundColor Green }
function Fail {
    param([string]$Msg)
    Write-Host ''
    Write-Host "  [FAIL] $Msg" -ForegroundColor Red
    Write-Host ''
    exit 1
}

# Docker run args to bind-mount the repo at /sm64 (shared by build + key derivation).
$MountArgs = @('--mount', "type=bind,source=$RepoRoot,destination=/sm64")

Write-Host ''
Write-Host '  sm64-nostr  ::  event ROM build wizard' -ForegroundColor Magenta

# --- Stage 1: baserom preflight (always first) -------------------------------
Write-Stage 1 'Baserom preflight'
Write-Step "Looking for baserom.us.z64 at its fixed location:"
Write-Step "    $BaseRom"
if (-not (Test-Path $BaseRom)) {
    Fail @"
No baserom found. Place an unmodified US Super Mario 64 ROM at exactly:

    $BaseRom

(this exact path -- it is not configurable), then rerun .\build.ps1
Expected SHA1: $($BaseRomSha1.ToLower())
"@
}
$actualSha1 = (Get-FileHash -Path $BaseRom -Algorithm SHA1).Hash
if ($actualSha1 -ne $BaseRomSha1) {
    Fail @"
Wrong baserom. The file at $BaseRom does not match the expected US ROM.

    expected SHA1: $($BaseRomSha1.ToLower())
    got SHA1:      $($actualSha1.ToLower())

Replace it with the correct unmodified US ROM and rerun .\build.ps1
"@
}
Write-Ok "baserom present and SHA1 verified"

# --- Stage 2: Docker image ---------------------------------------------------
Write-Stage 2 'Docker image'
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Fail "docker not found on PATH. Install Docker Desktop and start it, then rerun .\build.ps1"
}
$imageExists = $false
try { docker image inspect $ImageName 2>&1 | Out-Null; $imageExists = ($LASTEXITCODE -eq 0) } catch { $imageExists = $false }
if ($RebuildImage -or -not $imageExists) {
    if ($RebuildImage) { Write-Step "Rebuilding '$ImageName' image (forced)..." }
    else               { Write-Step "Image '$ImageName' not found -- building it (one-time, slow)..." }
    docker build -t $ImageName $RepoRoot
    if ($LASTEXITCODE -ne 0) { Fail "docker build failed. Is Docker Desktop running?" }
    Write-Ok "image '$ImageName' ready"
} else {
    Write-Ok "image '$ImageName' already present (use -RebuildImage to force)"
}

# --- Stage 3: key provisioning (ephemeral, per-event) ------------------------
Write-Stage 3 'Signing key'
$keyHex = $null
if ($PrivKey)  { $keyHex = $PrivKey.Trim().ToLower() }
elseif (-not $Yes) {
    Write-Step "Press ENTER to mint a FRESH ephemeral key (default),"
    Write-Step "or paste a 64-char hex secret to reuse a prior event's key:"
    $entered = Read-Host "  key (hex, or blank for fresh)"
    if ($entered.Trim()) { $keyHex = $entered.Trim().ToLower() }
}
if ($keyHex) {
    if ($keyHex -notmatch '^[0-9a-f]{64}$') {
        Fail "Supplied key is not 64 hex chars (got $($keyHex.Length)). Expected a raw 32-byte secp256k1 secret in hex."
    }
    Write-Ok "using supplied key (will overwrite any existing key file)"
} else {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $buf = New-Object byte[] 32
        $rng.GetBytes($buf)
        $keyHex = -join ($buf | ForEach-Object { $_.ToString('x2') })
    } finally { $rng.Dispose() }
    Write-Ok "minted a fresh ephemeral key"
}
if (-not (Test-Path $KeyDir)) { New-Item -ItemType Directory -Path $KeyDir | Out-Null }
# Fixed newline, no BOM -- matches gen_event_key.py output the generators expect.
[System.IO.File]::WriteAllText($KeyFile, $keyHex + "`n", (New-Object System.Text.UTF8Encoding($false)))
Write-Step "wrote $KeyFile"

# --- Stage 4: event name (REQUIRED, spec #75 sub-issue #76) ------------------
Write-Stage 4 'Event name'
if (-not $EventName -and -not $Yes) {
    Write-Step "Every event ROM must state, honestly and locally, which event"
    Write-Step "it was built for -- this is shown in the castle HUD corner."
    Write-Step "A-Z, 0-9, and space only (case-folded to upper), 17 chars max."
    $EventName = Read-Host "  event name (e.g. SUMMER JAM 2026)"
}
if (-not $EventName -or -not $EventName.Trim()) {
    Fail @"
No -EventName supplied. An event ROM cannot be built without one (spec #75,
sub-issue #76) -- the build refuses to produce a nameless binary.

Pass one, e.g.: .\build.ps1 -EventName "SUMMER JAM 2026"
(A-Z, 0-9, space only after case-folding; 17 chars max -- the actual
charset/length gate runs inside the container via gen_event_profile.py and
will FATAL out with a clear reason if this value doesn't pass it.)
"@
}
Write-Ok "event name '$EventName' will be baked into this build (validated inside the container)"

# --- Stage 5: build ----------------------------------------------------------
Write-Stage 5 'Build (Docker)'
# Single-quote the event name for the container's `sh -c`, escaping any
# embedded single quotes ('\'' is the standard sh idiom) -- gen_event_
# profile.py's own charset gate is the real validator; this quoting only
# has to survive shell parsing, not pre-validate the content.
$shSafeEventName = $EventName -replace "'", "'\''"
$makeCmd = 'make VERSION=us COMPARE=0 COMPILER=gcc -j"$(nproc)" PIPELINE_EVENT_NAME=' + "'" + $shSafeEventName + "'"
if ($Clean) {
    Write-Step "Scratch build requested -- running 'make clean' first."
    $makeCmd = 'make clean && ' + $makeCmd
}
Write-Step "Streaming build output (this takes a while)..."
Write-Host ''
& docker run --rm @MountArgs $ImageName sh -c $makeCmd
if ($LASTEXITCODE -ne 0) { Fail "make failed (exit $LASTEXITCODE). See the build output above." }
if (-not (Test-Path $RomPath)) { Fail "make reported success but no ROM at $RomPath" }
Write-Host ''
Write-Ok "ROM built"

# --- Stage 6: summary panel --------------------------------------------------
Write-Stage 6 'Summary'

# npub: prefer the manifest the build actually baked; fall back to deriving it.
$npub = $null
if (Test-Path $ManifestPath) {
    try { $npub = (Get-Content -Raw $ManifestPath | ConvertFrom-Json).npub } catch { $npub = $null }
}

# nsec (+ npub fallback): derive from the same vendored codec inside the container.
$pyCode = 'import sys; sys.path.insert(0,"/sm64/tools"); from nostr_secp256k1 import derive_xonly_pubkey, bech32_encode, npub_from_xonly_pubkey; b=bytes.fromhex(open("/sm64/keys/event_privkey.hex").read().strip()); print(bech32_encode("nsec", b)); print(npub_from_xonly_pubkey(derive_xonly_pubkey(b)))'
$nsec = $null
# Windows PowerShell 5.1 strips embedded double quotes when passing args to a
# native exe (docker.exe), which corrupts the one-liner into invalid Python.
# Backslash-escape them so the C runtime forwards literal quotes to python3.
$pyCodeArg = $pyCode -replace '"', '\"'
try {
    $derived = & docker run --rm @MountArgs $ImageName python3 -c $pyCodeArg
    if ($LASTEXITCODE -eq 0 -and $derived) {
        $nsec = $derived[0]
        if (-not $npub -and $derived.Count -gt 1) { $npub = $derived[1] }
    }
} catch { $nsec = $null }

$romSha1 = (Get-FileHash -Path $RomPath -Algorithm SHA1).Hash.ToLower()

Write-Host ''
Write-Host ("+" + ("-" * 66) + "+") -ForegroundColor Green
Write-Host "|  IT CAME OUT" -ForegroundColor Green
Write-Host ("+" + ("-" * 66) + "+") -ForegroundColor Green
Write-Host "  ROM        : $RomPath"
Write-Host "  ROM SHA1   : $romSha1"
Write-Host ''
Write-Host "  This ROM's ephemeral event identity -- SAVE IT NOW if you want to" -ForegroundColor Yellow
Write-Host "  reuse or broadcast it; it changes every build:" -ForegroundColor Yellow
Write-Host "    npub     : $(if ($npub) { $npub } else { '(unavailable)' })"
Write-Host "    nsec     : $(if ($nsec) { $nsec } else { '(unavailable)' })"
Write-Host "    hex      : $keyHex"
Write-Host ''
