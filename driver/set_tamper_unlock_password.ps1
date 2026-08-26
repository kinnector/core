# Phase 7 step 10 addendum: configures the password that can unlock a
# tamper-protected kinnector_filter for one unload attempt - see
# driver/kinnector_filter/tamper_unlock.h for the full design and its own
# honest caveat about \Parameters not being ACL-hardened in this project's
# current dev/test-scaffolding form.
#
# Hashes the password with SHA-256 over its raw UTF-16LE bytes - this MUST
# match exactly how tamper_unlock.c hashes the registry-read REG_SZ value
# (a UNICODE_STRING's buffer is already UTF-16LE, no re-encoding happens on
# the driver side), which is why this script uses
# [System.Text.Encoding]::Unicode (.NET's name for UTF-16LE) rather than
# UTF8 or any other encoding.
#
# Usage: .\set_tamper_unlock_password.ps1 -Password "correct horse battery staple"
# Must run elevated (writes under HKLM\...\Services\kinnector_filter\Parameters).
# Run this BEFORE loading the driver with TestTamperProtectionEnabled=1 -
# there is no way to configure this after the fact without normal registry
# write access, and no way to unlock without it configured first.
#
# To actually unlock a running tamper-protected driver for one unload:
#   reg add "HKLM\SYSTEM\CurrentControlSet\Services\kinnector_filter\Parameters" /v TamperProtectionUnlockAttempt /t REG_SZ /d "<password>" /f
#   sc stop kinnector_filter
# (Value name has no Test- prefix, unlike other scaffolding values, since
# this one isn't a test/observation flag - it's the actual secret exchange.
# Grep tamper_unlock.c if this comment and the code ever drift.)

param(
    [Parameter(Mandatory = $true)]
    [string]$Password
)

$ServiceName = "kinnector_filter"
$ParametersPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName\Parameters"

if (-not (Test-Path $ParametersPath)) {
    New-Item -Path $ParametersPath -Force | Out-Null
}

$bytes = [System.Text.Encoding]::Unicode.GetBytes($Password)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $hash = $sha256.ComputeHash($bytes)
} finally {
    $sha256.Dispose()
}

Set-ItemProperty -Path $ParametersPath -Name "TamperProtectionUnlockHash" -Value $hash -Type Binary

Write-Host "Stored SHA-256 hash ($([System.BitConverter]::ToString($hash).Replace('-', '').ToLower())) at $ParametersPath\TamperProtectionUnlockHash"
Write-Host "Reminder: this value is NOT ACL-protected in this project's current form - see tamper_unlock.h's caveat."
