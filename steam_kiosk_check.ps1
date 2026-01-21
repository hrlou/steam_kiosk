# steam_kiosk_check.ps1
# Checks the status of Autologin and Big-Picture shell for the Steam Kiosk user

# ========================================
# Constants
# ========================================
$SteamUser = "steam_kiosk"
$WinlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$KioskHivePath = "C:\Users\$SteamUser\NTUSER.DAT"
$HiveName = "STEAM_KIOSK"

# ========================================
# Autologin Status
# ========================================
Write-Host "=== Autologin Status ==="

try {
    $AutoAdminLogon = Get-ItemPropertyValue -Path $WinlogonKey -Name "AutoAdminLogon" -ErrorAction Stop
    $DefaultUser = Get-ItemPropertyValue -Path $WinlogonKey -Name "DefaultUserName" -ErrorAction Stop
    $DefaultPassword = Get-ItemPropertyValue -Path $WinlogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue

    Write-Host "AutoAdminLogon : $AutoAdminLogon"
    Write-Host "DefaultUserName: $DefaultUser"
    Write-Host "DefaultPassword: $DefaultPassword"
    if ($AutoAdminLogon -eq "1" -and $DefaultUser -eq $SteamUser) {
        Write-Host "Autologin is ENABLED for $SteamUser`n"
    } else {
        Write-Host "Autologin is DISABLED`n"
    }
} catch {
    Write-Host "Failed to read autologin registry keys."
}

# ========================================
# Big-Picture Shell Status
# ========================================
Write-Host "=== Big-Picture Shell Status ==="

# Load the kiosk hive temporarily
try {
    if (!(Test-Path "HKU:\$HiveName")) {
        reg load "HKU\$HiveName" "$KioskHivePath" | Out-Null
    }

    $ShellValue = Get-ItemPropertyValue -Path "HKU:\$HiveName\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -ErrorAction Stop
    Write-Host "Shell registry value: $ShellValue"

    if ($ShellValue -like "*Steam.exe*") {
        Write-Host "Big-Picture shell is ENABLED`n"
    } else {
        Write-Host "Big-Picture shell is DISABLED`n"
    }
} catch {
    Write-Host "Failed to read Big-Picture shell registry key."
} finally {
    # Unload the hive if it was loaded
    if (Test-Path "HKU:\$HiveName") {
        reg unload "HKU\$HiveName" | Out-Null
    }
}
