<#
.SYNOPSIS
    Windows Guide-Review Demo Runner for ips_project (Prompt 8).
    Runs from any working directory:
      1. Unit test suite (UNIT TEST)
      2. Claims & title consistency audit (UNIT TEST)
      3. End-to-end synthetic smoke pipeline + watermarked figures (SYNTHETIC SMOKE)
    Prints PASS/FAIL per step and a final summary table.
    NOTE: No Linux/XDP/kernel/real-testbed code is run by this script.
#>

$ErrorActionPreference = "Continue"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot  = (Resolve-Path (Join-Path $ScriptDir "..")).Path

$env:OMP_NUM_THREADS = "4"
$env:MKL_NUM_THREADS = "4"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  IPS Project -- Windows Guide-Review Demo (Prompt 8/9)" -ForegroundColor Cyan
Write-Host "  Repo: $RepoRoot" -ForegroundColor Cyan
Write-Host "  Scope: UNIT TEST + SYNTHETIC SMOKE ONLY (No Linux/kernel/testbed run)" -ForegroundColor Yellow
Write-Host "========================================================================" -ForegroundColor Cyan

$Results = @()
$TotalStart = Get-Date

function Invoke-DemoStep {
    param(
        [string]$StepName,
        [string]$EvidenceType,
        [string[]]$CmdArgs
    )
    Write-Host "`n[*] Running: $StepName [$EvidenceType] ..." -ForegroundColor White
    $t0 = Get-Date
    Push-Location $RepoRoot
    try {
        & python @CmdArgs | Out-Host
        $rc = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    $elapsed = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $status = if ($rc -eq 0) { "PASS" } else { "FAIL (rc=$rc)" }
    $color  = if ($rc -eq 0) { "Green" } else { "Red" }
    Write-Host "    -> $status (${elapsed}s)" -ForegroundColor $color
    return [PSCustomObject]@{
        Step         = $StepName
        EvidenceType = $EvidenceType
        Status       = $status
        DurationSec  = $elapsed
    }
}

$Results += Invoke-DemoStep -StepName "1. Unit Test Suite (pytest -q)" -EvidenceType "UNIT TEST" -CmdArgs @("-m", "pytest", "-q")
$Results += Invoke-DemoStep -StepName "2. Claims & Title Audit (check_claims.py)" -EvidenceType "UNIT TEST" -CmdArgs @("audit/check_claims.py")

$SmokeScript = Join-Path $RepoRoot "demo\run_smoke_pipeline.py"
if (Test-Path $SmokeScript) {
    $Results += Invoke-DemoStep -StepName "3. Synthetic Smoke Pipeline & Figures" -EvidenceType "SYNTHETIC SMOKE" -CmdArgs @("demo/run_smoke_pipeline.py", "--fast")
} else {
    Write-Host "`n[!] demo/run_smoke_pipeline.py not yet present; skipping step 3." -ForegroundColor Yellow
    $Results += [PSCustomObject]@{
        Step         = "3. Synthetic Smoke Pipeline & Figures"
        EvidenceType = "SYNTHETIC SMOKE"
        Status       = "SKIP (not created yet)"
        DurationSec  = 0.0
    }
}

$TotalSec = [math]::Round(((Get-Date) - $TotalStart).TotalSeconds, 1)
Write-Host "`n========================================================================" -ForegroundColor Cyan
Write-Host "  FINAL DEMO SUMMARY (Total: ${TotalSec}s)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
$Results | Format-Table -AutoSize

$AnyFail = $Results | Where-Object { $_.Status -like "FAIL*" }
if ($AnyFail) {
    Write-Host "OVERALL: FAIL" -ForegroundColor Red
    exit 1
} else {
    Write-Host "OVERALL: PASS (UNIT TEST + SYNTHETIC SMOKE ONLY -- No Linux/kernel/real-testbed result)" -ForegroundColor Green
    exit 0
}
