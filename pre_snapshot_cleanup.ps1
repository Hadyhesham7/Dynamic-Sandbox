# ============================================================
# pre_snapshot_cleanup.ps1
# Run this as ADMINISTRATOR on the GCP server BEFORE taking
# the clean snapshot. It removes ALL traces of api_exerciser3.exe
# and any other test artifacts.
# ============================================================

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  KNOWHOW Pre-Snapshot Cleanup Script" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

# ── 1. Kill any leftover test processes ──────────────────────
Write-Host "`n[1/8] Killing leftover processes..." -ForegroundColor Yellow
$procs = @("api_exerciser3", "payload", "sandbox_test")
foreach ($p in $procs) {
    Get-Process -Name $p -ErrorAction SilentlyContinue | Stop-Process -Force
}
Write-Host "  Done." -ForegroundColor Green

# ── 2. Delete files created by api_exerciser3.exe ────────────
Write-Host "`n[2/8] Removing malware test artifacts..." -ForegroundColor Yellow

# Temp staging directory
$tempPaths = @(
    "$env:TEMP\sandbox_test_staging",
    "$env:TEMP\sandbox_test_config.dat",
    "$env:LOCALAPPDATA\Temp\sandbox_test_staging",
    "$env:LOCALAPPDATA\Temp\sandbox_test_config.dat"
)
# Also check all user profiles
$userProfiles = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
foreach ($user in $userProfiles) {
    $tempPaths += "$($user.FullName)\AppData\Local\Temp\sandbox_test_staging"
    $tempPaths += "$($user.FullName)\AppData\Local\Temp\sandbox_test_config.dat"
}

foreach ($p in $tempPaths) {
    if (Test-Path $p) {
        Remove-Item -Recurse -Force $p -ErrorAction SilentlyContinue
        Write-Host "  Deleted: $p" -ForegroundColor Green
    }
}

# ── 3. Clean registry persistence keys ───────────────────────
Write-Host "`n[3/8] Cleaning registry modifications..." -ForegroundColor Yellow

# The api_exerciser3 modified TaskCache DynamicInfo
# We remove only the specific test entries, not the entire key
$regPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($regPath in $regPaths) {
    if (Test-Path $regPath) {
        # Look for sandbox-related entries
        $subkeys = Get-ChildItem $regPath -ErrorAction SilentlyContinue
        foreach ($key in $subkeys) {
            try {
                $values = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                $valStr = ($values | Out-String).ToLower()
                if ($valStr -match "sandbox_test|api_exerciser|payload\.dll") {
                    Remove-Item $key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  Removed registry key: $($key.PSPath)" -ForegroundColor Green
                }
            } catch {}
        }
    }
}
Write-Host "  Registry cleaned." -ForegroundColor Green

# ── 4. Delete sandbox reports and uploads ────────────────────
Write-Host "`n[4/8] Wiping sandbox reports and uploads..." -ForegroundColor Yellow

# Adjust this path to your actual project location
$projectRoot = "C:\Users\$env:USERNAME\Desktop\Dynamic Sandbox(Hendy)"

$wipeDirs = @(
    "$projectRoot\uploads",
    "$projectRoot\sandbox\reports",
    "$projectRoot\URLLLL\screenshots",
    "$projectRoot\screenshots"
)

foreach ($d in $wipeDirs) {
    if (Test-Path $d) {
        Remove-Item -Recurse -Force $d -ErrorAction SilentlyContinue
        Write-Host "  Wiped: $d" -ForegroundColor Green
    }
}

# ── 5. Clear Windows Temp completely ─────────────────────────
Write-Host "`n[5/8] Clearing Windows temp files..." -ForegroundColor Yellow
Remove-Item -Recurse -Force "$env:TEMP\*" -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force "C:\Windows\Temp\*" -ErrorAction SilentlyContinue
Write-Host "  Temp cleared." -ForegroundColor Green

# ── 6. Clear browser cache (Playwright Chromium) ─────────────
Write-Host "`n[6/8] Clearing browser caches..." -ForegroundColor Yellow
$browserCaches = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
    "$env:LOCALAPPDATA\ms-playwright"
)
# Don't delete Playwright itself, just clear its cache
foreach ($cache in $browserCaches) {
    if (Test-Path "$cache\Cache_Data") {
        Remove-Item -Recurse -Force "$cache\Cache_Data" -ErrorAction SilentlyContinue
        Write-Host "  Cleared: $cache" -ForegroundColor Green
    }
}
Write-Host "  Browser caches cleared." -ForegroundColor Green

# ── 7. Clear Event Logs (optional — cleaner snapshot) ────────
Write-Host "`n[7/8] Clearing Windows Event Logs..." -ForegroundColor Yellow
wevtutil cl Application 2>$null
wevtutil cl System 2>$null
wevtutil cl Security 2>$null
Write-Host "  Event logs cleared." -ForegroundColor Green

# ── 8. Clear DNS cache and ARP table ─────────────────────────
Write-Host "`n[8/8] Flushing network caches..." -ForegroundColor Yellow
ipconfig /flushdns | Out-Null
arp -d * 2>$null
Write-Host "  Network caches flushed." -ForegroundColor Green

# ── Summary ──────────────────────────────────────────────────
Write-Host "`n============================================" -ForegroundColor Cyan
Write-Host "  CLEANUP COMPLETE!" -ForegroundColor Green
Write-Host "  Your VM is now clean." -ForegroundColor Green
Write-Host "" -ForegroundColor Cyan
Write-Host "  NEXT STEPS:" -ForegroundColor Yellow
Write-Host "  1. Stop the VM from GCP Console" -ForegroundColor White
Write-Host "  2. Go to Compute Engine > Disks" -ForegroundColor White
Write-Host "  3. Click your boot disk > CREATE SNAPSHOT" -ForegroundColor White
Write-Host "  4. Name it: sandbox-clean-v1" -ForegroundColor White
Write-Host "  5. Start the VM again" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
