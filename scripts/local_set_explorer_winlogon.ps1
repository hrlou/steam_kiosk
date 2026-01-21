$winlogon = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

Set-ItemProperty `
    -Path $winlogon `
    -Name Shell `
    -Value "explorer.exe"

