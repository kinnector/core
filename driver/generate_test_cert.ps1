# Generates a self-signed, KERNEL-MODE-CODE-SIGNING-capable test certificate
# for signing driver/ builds under `bcdedit /set testsigning on` mode ONLY.
# NOT a substitute for the real EV code-signing certificate / Microsoft
# Hardware Dev Center WHCP submission WINDOWS_COVERAGE_PLAN.md Phase 7
# already tracks as its own external workstream - this cert is rejected by
# any machine not running in test-signing mode, by design.
#
# Simpler than PPLRunner's generate_cert.ps1: that script also computes an
# ELAM-specific TBS (to-be-signed) hash for the ELAM certificate-info
# resource, which only ELAM drivers need. A plain kernel-mode driver like
# this one just needs a normal code-signing certificate with the Kernel Mode
# Code Signing + Code Signing EKUs - no TBS hash step required.

$password = "Kinnector-DriverTest-Dev-2026"
$certFolder = "Cert:\CurrentUser\My"

$cert = New-SelfSignedCertificate `
    -certstorelocation $certFolder `
    -HashAlgorithm SHA256 `
    -Subject "CN=kinnector_filter_test" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.4.1.311.61.4.1,1.3.6.1.5.5.7.3.3")

$passwordSecure = ConvertTo-SecureString -String $password -Force -AsPlainText
$outputFilename = Join-Path $PSScriptRoot "kinnector_filter_test.pfx"
Export-PfxCertificate -cert $cert -FilePath $outputFilename -Password $passwordSecure

Remove-Item "$certFolder\$($cert.Thumbprint)"
Write-Host "Written test cert to $outputFilename"
