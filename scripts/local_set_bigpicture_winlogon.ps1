$steamPath = "C:\Program Files (x86)\Steam\steam.exe"
$steamArgs = "-bigpicture"

$winlogon = "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

Set-ItemProperty `
    -Path $winlogon `
    -Name Shell `
    -Value "`"$steamPath`" $steamArgs"
