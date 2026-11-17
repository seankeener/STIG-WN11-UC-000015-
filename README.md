
# STIG-WN11-UC-000015-# WN11-UC-000015

Toast notifications to the lock screen must be turned off.

```powershell
<#
.SYNOPSIS
    This PowerShell script ensures that toast notifications on the lock screen are turned off (NoToastApplicationNotificationOnLockScreen = 1) for every user profile on the system, including the Default profile used for new users.

.NOTES
    Author          : Sean Keener
    LinkedIn        : https://www.linkedin.com/in/sean-k-308049210/
    GitHub          : github.com/seankeener
    Date Created    : 2026-11-15
    Last Modified   : 2026-11-15
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UC-000015
    Documentation   : https://stigaview.com/products/win11/v2r7/WN11-UC-000015/

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : 
    PowerShell Ver. : 

.USAGE
    Run from an elevated PowerShell prompt. The script applies the fix automatically and the window stays open when it finishes.
    This is a user-level (HKCU) setting, so the script updates every loaded user hive, loads and updates the hive of each
    profile that is not currently logged on, and updates the Default profile template so new users inherit the setting.
    Example syntax:
    PS C:\> .\WN11-UC-000015.ps1
    Result codes: 0 = all profiles compliant, 2 = error on at least one profile (stored in $LASTEXITCODE)
#>

[CmdletBinding()]
param()

$StigId      = 'WN11-UC-000015'
$SubKey      = 'SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'
$RegName     = 'NoToastApplicationNotificationOnLockScreen'
$Required    = 1
$ProfileList = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'

# Applies the setting inside one hive that is already mounted under HKEY_USERS.
# Returns 'Compliant', 'Remediated' or 'Error'.
function Set-PolicyForHive {
    param(
        [string]$HiveName,
        [string]$Label
    )

    $key = "Registry::HKEY_USERS\$HiveName\$SubKey"

    try {
        $current = (Get-ItemProperty -Path $key -Name $RegName -ErrorAction SilentlyContinue).$RegName

        if ($null -ne $current -and $current -eq $Required) {
            Write-Host "[$StigId] ALREADY COMPLIANT - $Label ($RegName is $current)" -ForegroundColor Green
            return 'Compliant'
        }

        $shown = if ($null -eq $current) { 'not set' } else { $current }
        Write-Host "[$StigId] NON-COMPLIANT - $Label ($RegName is $shown, required: $Required). Applying fix..." -ForegroundColor Yellow

        if (-not (Test-Path -Path $key)) {
            New-Item -Path $key -Force | Out-Null
        }
        New-ItemProperty -Path $key -Name $RegName -Value $Required -PropertyType DWord -Force | Out-Null

        $after = (Get-ItemProperty -Path $key -Name $RegName -ErrorAction SilentlyContinue).$RegName
        if ($null -ne $after -and $after -eq $Required) {
            Write-Host "[$StigId] REMEDIATED - $Label ($RegName set to $after)" -ForegroundColor Green
            return 'Remediated'
        }

        Write-Host "[$StigId] ERROR - $Label - value did not persist after applying the fix." -ForegroundColor Red
        return 'Error'
    }
    catch {
        Write-Host "[$StigId] ERROR - $Label - $($_.Exception.Message)" -ForegroundColor Red
        return 'Error'
    }
}

# Loads NTUSER.DAT from a profile folder, applies the setting, then unloads it.
function Set-PolicyForOfflineProfile {
    param(
        [string]$Label,
        [string]$ProfileDir,
        [string]$TempName
    )

    $hiveFile = Join-Path -Path $ProfileDir -ChildPath 'NTUSER.DAT'
    if (-not (Test-Path -Path $hiveFile -PathType Leaf)) {
        Write-Host "[$StigId] SKIPPED - $Label (NTUSER.DAT not found at $hiveFile)" -ForegroundColor DarkYellow
        return 'Skipped'
    }

    & reg.exe load "HKU\$TempName" "$hiveFile" 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[$StigId] ERROR - $Label - could not load $hiveFile (file may be in use)." -ForegroundColor Red
        return 'Error'
    }

    $status = 'Error'
    try {
        $status = Set-PolicyForHive -HiveName $TempName -Label $Label
    }
    finally {
        # Release handles so the hive can be unloaded
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()

        $unloaded = $false
        for ($i = 0; $i -lt 5 -and -not $unloaded; $i++) {
            & reg.exe unload "HKU\$TempName" 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $unloaded = $true
            }
            else {
                Start-Sleep -Milliseconds 500
                [gc]::Collect()
            }
        }
        if (-not $unloaded) {
            Write-Host "[$StigId] ERROR - $Label - could not unload temporary hive HKU\$TempName. Reboot or run 'reg unload HKU\$TempName'." -ForegroundColor Red
            $status = 'Error'
        }
    }
    return $status
}

function Invoke-StigFix {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[$StigId] ERROR - This script must be run as Administrator." -ForegroundColor Red
        return 2
    }

    try {
        $counts = @{ Compliant = 0; Remediated = 0; Skipped = 0; Error = 0 }
        $index  = 0

        # 1. Every user profile registered on the system (local, domain and Entra ID accounts)
        $userProfiles = Get-ChildItem -Path $ProfileList |
            Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' }

        foreach ($p in $userProfiles) {
            $sid        = $p.PSChildName
            $profileDir = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -Path $p.PSPath).ProfileImagePath)
            $label      = "Profile $profileDir ($sid)"

            if (Test-Path -Path "Registry::HKEY_USERS\$sid") {
                # User is logged on, hive is already loaded
                $status = Set-PolicyForHive -HiveName $sid -Label $label
            }
            else {
                $index++
                $status = Set-PolicyForOfflineProfile -Label $label -ProfileDir $profileDir -TempName "STIG_TMP_$index"
            }
            $counts[$status]++
        }

        # 2. Default profile template so any new user inherits the setting
        $defaultDir = (Get-ItemProperty -Path $ProfileList -ErrorAction SilentlyContinue).Default
        if ([string]::IsNullOrWhiteSpace($defaultDir)) { $defaultDir = "$env:SystemDrive\Users\Default" }
        $defaultDir = [Environment]::ExpandEnvironmentVariables($defaultDir)

        $status = Set-PolicyForOfflineProfile -Label "Default profile template ($defaultDir)" -ProfileDir $defaultDir -TempName 'STIG_DEFAULT'
        $counts[$status]++

        Write-Host ""
        Write-Host "[$StigId] SUMMARY - Already compliant: $($counts.Compliant) | Remediated: $($counts.Remediated) | Skipped: $($counts.Skipped) | Errors: $($counts.Error)"

        if ($counts.Error -gt 0) { return 2 }
        return 0
    }
    catch {
        Write-Host "[$StigId] ERROR - $($_.Exception.Message)" -ForegroundColor Red
        return 2
    }
}

$result = 2
try {
    $result = Invoke-StigFix
}
finally {
    $global:LASTEXITCODE = $result
    Write-Host ""
    Read-Host "Press Enter to close this window" | Out-Null
}
```
