cl /std:c++20 /nologo /W4 /O2 /MT steam_kiosk.cpp `
  /link /SUBSYSTEM:WINDOWS `
  /MANIFEST:EMBED `
  /MANIFESTINPUT:steam_kiosk.manifest `
  /MANIFESTUAC:NO `
  user32.lib advapi32.lib shell32.lib netapi32.lib gdi32.lib Wtsapi32.lib 
