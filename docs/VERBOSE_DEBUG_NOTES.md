# Shell Switching Debug Enhancements

## Problem Identified
The shell value was being set (SUCCESS logged), but then immediately when checking status again, it was returning "Cannot read shell value. Status: 2" (ERROR_FILE_NOT_FOUND). This suggests the Shell registry value is not being persisted or is somehow disappearing.

## Root Cause (Hypothesis)
The Winlogon registry key path may not exist in the user hive, so the value is being set on a key that gets unloaded before it can be written to disk.

## Changes Made

### 1. Enhanced `kiosk_set_shell()` - Now Uses RegCreateKeyEx
**Old approach:** Used RegOpenKeyEx - would fail if path didn't exist
**New approach:** Uses RegCreateKeyEx - creates the key if it doesn't exist

```cpp
// BEFORE: Just try to open
RegOpenKeyExW(HKEY_USERS, path, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &key);

// AFTER: Create if doesn't exist
RegCreateKeyExW(HKEY_USERS, path, 0, nullptr, REG_OPTION_NON_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &path_key, nullptr);
```

### 2. Massive Debug Logging
Added VERBOSE logging at every step to track exactly what's happening:

```
VERBOSE: Winlogon registry path created/opened successfully
VERBOSE: Writing shell value - Size: 96 bytes, Command length: 47 chars
VERBOSE: RegSetValueExW returned status: 0
VERBOSE: Attempting to verify written shell value...
VERBOSE: RegQueryValueExW verification returned status: 0
VERBOSE: Type: 1 (should be 1 for REG_SZ)
VERBOSE: Read back shell value: C:\Program Files (x86)\Steam\steam.exe -bigpicture
VERBOSE: Verification size: 96 bytes
VERBOSE: RegFlushKey called
SUCCESS: Shell set and verified: C:\Program Files (x86)\Steam\steam.exe -bigpicture
```

### 3. Enhanced Verification Output
If verification fails, now shows exactly what was wrong:

```
ERROR: Shell value verification failed!
  - QueryStatus: 2
  - Type match: NO
  - Expected: C:\Program Files (x86)\Steam\steam.exe -bigpicture
  - Got: (nothing read)
```

### 4. Updated `update_ui()` - Verbose Tracing
Now logs every time UI is refreshed:

```
VERBOSE: update_ui() called - refreshing all UI elements
VERBOSE: autologin_status() returned: 0
VERBOSE: kiosk_shell_status() returned: 1, setting checkbox to: 1
VERBOSE: update_ui() complete
```

### 5. Enhanced `kiosk_shell_status()` - Better Diagnostics
Added more detailed logging when checking status:

```
VERBOSE: About to query Shell value from registry...
VERBOSE: RegQueryValueExW returned status: 0, Type: 1, Size: 96
VERBOSE: Shell value read successfully: C:\Program Files (x86)\Steam\steam.exe -bigpicture
INFO: Shell status check - Value: 'C:\Program Files (x86)\Steam\steam.exe -bigpicture', IsBigPicture: 1
```

### 6. Button Click Logging
Each button now logs when clicked:

```
VERBOSE: User clicked Big Picture shell button
INFO: Setting kiosk shell to: C:\Program Files (x86)\Steam\steam.exe -bigpicture
```

## What To Look For in Logs

### Success Case
```
INFO: Setting kiosk shell to: C:\Program Files (x86)\Steam\steam.exe -bigpicture
VERBOSE: Writing shell value - Size: 96 bytes, Command length: 47 chars
VERBOSE: RegSetValueExW returned status: 0
VERBOSE: Attempting to verify written shell value...
VERBOSE: RegQueryValueExW verification returned status: 0
VERBOSE: Read back shell value: C:\Program Files (x86)\Steam\steam.exe -bigpicture
SUCCESS: Shell set and verified: C:\Program Files (x86)\Steam\steam.exe -bigpicture
SUCCESS: Big Picture shell enabled
VERBOSE: kiosk_shell_status() returned: 1, setting checkbox to: 1
```

### Failure Case - Key Issues
```
ERROR: Failed to create/open Winlogon path. Status: 5
```
Status 5 = ERROR_ACCESS_DENIED (need privileges)

### Failure Case - Value Not Persisting
```
VERBOSE: RegSetValueExW returned status: 0
VERBOSE: RegQueryValueExW returned status: 2
```
Status 2 = ERROR_FILE_NOT_FOUND (value disappeared after hive unload)

## Testing Steps

1. **Run the application**
2. **Click Big Picture button**
3. **Check debug.log for the full flow**
4. **Look for any ERROR messages with status codes**
5. **Report any status codes found**

## Expected Debug Log Output

Should see something like:
```
[timestamp] VERBOSE: User clicked Big Picture shell button
[timestamp] INFO: Setting kiosk shell to: C:\Program Files (x86)\Steam\steam.exe -bigpicture
[timestamp] VERBOSE: Winlogon registry path created/opened successfully
[timestamp] VERBOSE: Writing shell value - Size: 96 bytes, Command length: 47 chars
[timestamp] VERBOSE: RegSetValueExW returned status: 0
[timestamp] VERBOSE: Attempting to verify written shell value...
[timestamp] VERBOSE: RegQueryValueExW verification returned status: 0
[timestamp] VERBOSE: Type: 1 (should be 1 for REG_SZ)
[timestamp] VERBOSE: Read back shell value: C:\Program Files (x86)\Steam\steam.exe -bigpicture
[timestamp] VERBOSE: Verification size: 96 bytes
[timestamp] VERBOSE: RegFlushKey called
[timestamp] SUCCESS: Shell set and verified: C:\Program Files (x86)\Steam\steam.exe -bigpicture
[timestamp] SUCCESS: Big Picture shell enabled
[timestamp] VERBOSE: update_ui() called - refreshing all UI elements
[timestamp] VERBOSE: kiosk_shell_status() returned: 1, setting checkbox to: 1
[timestamp] VERBOSE: update_ui() complete
```

## Key Improvement
The critical fix is using `RegCreateKeyEx` instead of `RegOpenKeyEx` to ensure the Winlogon registry path exists before trying to write the Shell value. This should prevent the ERROR_FILE_NOT_FOUND issue.

---

**Run this version and share the full debug.log output so we can see exactly what's happening at each step!**
