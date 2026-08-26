# Phase 7 step 10 (WINDOWS_COVERAGE_PLAN.md): service-ACL half of driver
# self-protection. Operational/install-time step, not driver code - `sc
# sdset` changes the kinnector_filter *service object's* own security
# descriptor in the SCM, independent of anything kinnector_filter.sys does.
#
# What this buys: an ordinary local Administrator running `sc stop
# kinnector_filter` / `sc delete kinnector_filter` / `sc config
# kinnector_filter ...` gets denied outright - Administrators (BA) are only
# granted query/enumerate/interrogate/read-control rights below, not
# start/stop/pause/change-config/delete/write-DAC/write-owner. SYSTEM (SY)
# keeps full control, matching how this driver's own service-management
# calls (this project's own install/uninstall tooling, run as SYSTEM or via
# an elevated path that impersonates it) still work.
#
# What this does NOT buy: resistance against a determined local admin.
# Windows lets any principal holding SeTakeOwnershipPrivilege (which local
# Administrators have by default) take ownership of the service object and
# rewrite its DACL regardless of what the DACL currently says - this is a
# structural property of the Windows security model, not a gap in this
# script. A fully privileged admin/SYSTEM/BYOVD-kernel attacker remains a
# residual risk exactly as WINDOWS_COVERAGE_PLAN.md step 10 itself states -
# this raises the bar against casual/scripted `sc stop`, it does not close
# that gap.
#
# SDDL ACE right-letter reference (service-specific ACCESS_MASK bits, same
# fixed letter-per-bit scheme `sc sdshow`/`sc sdset` already use):
#   CC = SERVICE_QUERY_CONFIG    DC = SERVICE_CHANGE_CONFIG
#   LC = SERVICE_QUERY_STATUS    SW = SERVICE_ENUMERATE_DEPENDENTS
#   RP = SERVICE_START           WP = SERVICE_STOP
#   DT = SERVICE_PAUSE_CONTINUE  LO = SERVICE_INTERROGATE
#   CR = SERVICE_USER_DEFINED_CONTROL
#   SD = DELETE  RC = READ_CONTROL  WD = WRITE_DAC  WO = WRITE_OWNER
#
# Usage: .\harden_service_acl.ps1            (apply hardened ACL)
#        .\harden_service_acl.ps1 -Revert    (restore Windows' stock default ACL)
# Must run elevated. Prints the resulting `sc sdshow` output either way so
# the actual applied state is always visible, not just assumed from this
# script's intent.

param(
    [switch]$Revert
)

$ServiceName = "kinnector_filter"

# Hardened: SYSTEM full control; Administrators, Interactive Users, and
# Service accounts get query/enumerate/interrogate/read-control ONLY - no
# start, stop, pause, change-config, delete, write-DAC, or write-owner.
$HardenedSddl = "D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWLOCRRC;;;BA)"

# Stock default SDDL Windows applies to most services - full control
# restored to SYSTEM and Administrators, same rights profile Interactive
# Users/Service accounts always had. This is what `-Revert` restores; it is
# NOT a copy of this specific service's original descriptor (that was never
# captured), but the well-documented Windows service default.
$DefaultSddl = "D:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;BA)"

if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
    Write-Error "Service '$ServiceName' is not registered - nothing to harden. Run this after 'sc create', before relying on ACL protection."
    exit 1
}

$targetSddl = if ($Revert) { $DefaultSddl } else { $HardenedSddl }
$action = if ($Revert) { "Reverting to stock default ACL" } else { "Applying hardened ACL" }

Write-Host "$action for service '$ServiceName'..."
sc.exe sdset $ServiceName $targetSddl

Write-Host "--- resulting security descriptor ---"
sc.exe sdshow $ServiceName
