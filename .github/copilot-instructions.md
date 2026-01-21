## Steam Kiosk — Copilot / AI contributor instructions

This repository is a small Windows helper app (single C++ source file) used to manage a dedicated "steam_kiosk" local user, its profile hive (NTUSER.DAT) and a Winlogon configuration that launches Steam in Big Picture mode.

Key files
- `steam_kiosk.cpp` — single-source C++ program (main logic). Read this file to understand UI, registry changes, user/profile lifecycle and privilege manipulation.
- `compile.ps1` — build entry; runs `cl` (MSVC). Use this from an elevated Developer PowerShell/VS environment.
- `local/NTUSER_BACKUP.DAT` — profile backup created by the program.
- `scripts/` — convenience PowerShell helpers for winlogon / profile tasks.

Big-picture architecture
- Single native Windows GUI helper. Responsibilities:
  - Ensure `steam_kiosk` user exists (NetUser* APIs).
  - Ensure a usable profile/hive (`NTUSER.DAT`) exists and provide backup/restore.
  - Toggle Winlogon autologin (HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon).
  - Modify the kiosk user's Shell in the user hive (HKCU equivalent under HKEY_USERS\STEAM_KIOSK).
  - Provide UI for logoff/restart/delete profile.

Critical patterns & safety rules (very important)
- NEVER load or write the live NTUSER.DAT directly. The code uses a safer pattern: copy `NTUSER.DAT` to a temporary file and call `RegLoadKeyW(HKEY_USERS, L"STEAM_KIOSK", temp_copy)` so operations occur on the loaded hive key and the live file is not modified while Windows may have it open.
- Always obtain required privileges before touching hives: `SE_BACKUP_NAME` and `SE_RESTORE_NAME` via AdjustTokenPrivileges (see `scoped_privileges`). Use the same pattern when adding new hive code.
- When writing REG_SZ values, pass the correct byte-length: `(wcslen(value)+1) * sizeof(wchar_t)`.
- Use `RegFlushKey` after writes when persistent state is required.

Registry and hive integration points
- Autologin keys (HKLM): `AutoAdminLogon`, `DefaultUserName`, `DefaultPassword`, `DefaultDomainName`.
- User hive key: `HKEY_USERS\STEAM_KIOSK\Software\Microsoft\Windows NT\CurrentVersion\Winlogon` — `Shell` value toggles Big Picture vs explorer.
- Backup/restore: `CopyFileW` is used to manage `local/NTUSER_BACKUP.DAT`.

Build / run / debug
- Build: open an elevated Developer PowerShell (so `cl` is on PATH) and run:

```powershell
.\compile.ps1
```

- Run the built `steam_kiosk.exe` as Administrator. Many operations require elevation (creating users, loading hives, editing HKLM).
- Debug: attach Visual Studio to the running helper process or run under the debugger from the generated EXE. Use Process Explorer to inspect loaded hives under HKEY_USERS.

Conventions & style notes (follow when editing)
- File-level organization: constants at top (paths as `inline constexpr auto`), then helpers grouped by responsibility (privileges, user mgmt, hive mgmt, UI). Preserve this group structure.
- Use `inline` helper functions for small utilities. Prefer `wchar_t`/wide APIs (`Reg*W`, `CreateWindowW`, etc.).
- Prefer RAII wrappers (existing `scoped_privileges`, `scoped_user_hive`) for resource safety.

Examples (patterns to follow)
- Load user hive safely:

  - copy `STEAM_KIOSK_HIVE` to a temp file with `CopyFileW`
  - call `RegLoadKeyW(HKEY_USERS, L"STEAM_KIOSK", temp_path)`
  - open `HKEY_USERS\STEAM_KIOSK\...` and call `RegGetValueW` / `RegSetValueExW`
  - call `RegUnLoadKeyW(HKEY_USERS, L"STEAM_KIOSK")` and delete temp file in destructor

- Registry write example (use exact byte length):

```cpp
RegSetValueExW(key, L"DefaultUserName", 0, REG_SZ,
               reinterpret_cast<const BYTE*>(STEAM_KIOSK_USER),
               static_cast<DWORD>((wcslen(STEAM_KIOSK_USER) + 1) * sizeof(wchar_t)));
```

What not to change without testing
- Avoid changing registry/hive logic without manual test steps on a disposable VM. Corrupting the kiosk user's `NTUSER.DAT` can make a user profile unusable.
- Do not remove `SE_BACKUP_NAME` / `SE_RESTORE_NAME` privilege code. These are required for hive operations.

Next steps for AI contributors
- If you modify hive loading/writing, add explicit comments explaining why a temp copy is used and add a manual test checklist in `README.md` for restore/backup flows.
- If you add new registry keys, follow the exact byte-length pattern and call `RegFlushKey` where appropriate.

If anything in this file seems unclear or a behavior is missing from the codebase, tell me what you need clarified (for example: platform/Windows versions tested, existing test VM steps, or expected behavior when a backup is missing) and I will update this guidance.
