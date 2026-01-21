// steam_kiosk.cpp
#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <lm.h>
#include <wtsapi32.h>
#include <shellapi.h>
#include <thread>
#include <ctime>

// ========================================
// Constants
// ========================================
inline constexpr auto LOCAL_PATH             = L"C:\\tools\\steam_shell\\local";
inline constexpr auto NTUSER_BACKUP_PATH     = L"C:\\tools\\steam_shell\\local\\NTUSER_BACKUP.DAT";
inline constexpr auto DEBUG_LOG_PATH         = L"C:\\tools\\steam_shell\\local\\debug.log";
inline constexpr auto STEAM_EXE_PATH         = L"C:\\Program Files (x86)\\Steam\\steam.exe";
inline constexpr auto BIG_PICTURE_EXEC       = L"C:\\Program Files (x86)\\Steam\\steam.exe -bigpicture";
inline constexpr auto STEAM_KIOSK_USER       = L"steam_kiosk";
inline constexpr auto STEAM_KIOSK_PASS       = L"valve";
inline constexpr auto STEAM_KIOSK_PROFILE_DIR = L"C:\\Users\\steam_kiosk";
inline constexpr auto STEAM_KIOSK_HIVE       = L"C:\\Users\\steam_kiosk\\NTUSER.DAT";

inline constexpr int MAIN_WINDOW_WIDTH       = 400;
inline constexpr int MAIN_WINDOW_HEIGHT      = 300;
inline constexpr int TOGGLE_WIDTH            = 112;  // ((400−(20×2))−(12×2))×1/3
inline constexpr int BUTTON_WIDTH            = 150;
inline constexpr int BUTTON_HEIGHT           = 40;
inline constexpr int FONT_SIZE               = 16;
inline constexpr int HIVE_VALIDATION_SIZE    = 4096;  // Minimum valid hive size

// ========================================
// Global Window Handles
// ========================================
HWND g_hwnd_title;
HWND g_hwnd_autologin;
HWND g_hwnd_shell;
HWND g_hwnd_users_prompt;
HWND g_hwnd_logoff;
HWND g_hwnd_restart;
HWND g_hwnd_delete_user;

// Single instance mutex - prevents multiple launches
HANDLE g_single_instance_mutex = nullptr;

// ========================================
// Forward declarations
// ========================================
void update_ui();
void prompt_first_login();
void switch_to_other_user_screen();
void kiosk_setup_if_needed();

// ========================================
// Debug Logging
// ========================================
inline void ensure_local_path() {
    CreateDirectoryW(LOCAL_PATH, nullptr);
}

inline void debug_log(const wchar_t* format, ...) {
    ensure_local_path();

    FILE* file = nullptr;
    _wfopen_s(&file, DEBUG_LOG_PATH, L"a");
    if (!file) {
        return;
    }

    // Get current timestamp
    time_t now = time(nullptr);
    struct tm timeinfo {};
    localtime_s(&timeinfo, &now);

    wchar_t timestamp[32] = {};
    wcsftime(timestamp, sizeof(timestamp) / sizeof(wchar_t), L"%Y-%m-%d %H:%M:%S", &timeinfo);

    fwprintf(file, L"[%s] ", timestamp);

    va_list args;
    va_start(args, format);
    vfwprintf(file, format, args);
    va_end(args);

    fwprintf(file, L"\n");
    fflush(file);
    fclose(file);
}

struct scoped_privileges {
    HANDLE token = nullptr;
    TOKEN_PRIVILEGES old_tp{};
    DWORD old_tp_size = sizeof(old_tp);

    explicit scoped_privileges(std::initializer_list<LPCWSTR> privs) {
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              &token))
            return;

        for (auto p : privs) {
            LUID luid;
            if (!LookupPrivilegeValueW(nullptr, p, &luid))
                continue;

            TOKEN_PRIVILEGES tp{};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(token, FALSE, &tp,
                                   sizeof(old_tp), &old_tp, &old_tp_size);
        }
    }

    ~scoped_privileges() {
        if (token) {
            AdjustTokenPrivileges(token, FALSE, &old_tp, 0, nullptr, nullptr);
            CloseHandle(token);
        }
    }
};

struct scoped_user_hive {
    const wchar_t* hive_name = L"STEAM_KIOSK";
    wchar_t temp_hive[MAX_PATH]{};
    bool loaded = false;

    // ========================================
    // NTUSER.DAT Validation
    // ========================================
    inline bool validate_hive_file(const wchar_t* path) {
        // Check if file exists and has minimum size
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
            debug_log(L"ERROR: Hive file not found: %s", path);
            return false;
        }

        // NTUSER.DAT should be at least 4KB
        ULARGE_INTEGER file_size;
        file_size.LowPart = fad.nFileSizeLow;
        file_size.HighPart = fad.nFileSizeHigh;

        if (file_size.QuadPart < HIVE_VALIDATION_SIZE) {
            debug_log(L"ERROR: Hive file is too small (%llu bytes). Possible corruption: %s",
                      file_size.QuadPart, path);
            return false;
        }

        // Check registry hive signature (first 4 bytes should be "regf")
        HANDLE h_file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h_file == INVALID_HANDLE_VALUE) {
            debug_log(L"ERROR: Cannot open hive file for validation: %s", path);
            return false;
        }

        BYTE signature[4] = {};
        DWORD bytes_read = 0;
        BOOL read_ok = ReadFile(h_file, signature, 4, &bytes_read, nullptr);
        CloseHandle(h_file);

        if (!read_ok || bytes_read != 4) {
            debug_log(L"ERROR: Cannot read hive signature from: %s", path);
            return false;
        }

        // Registry hive files should start with "regf" (0x72656766)
        if (signature[0] != 'r' || signature[1] != 'e' || 
            signature[2] != 'g' || signature[3] != 'f') {
            debug_log(L"ERROR: Invalid hive signature. File is corrupted: %s", path);
            return false;
        }

        debug_log(L"VALIDATED: Hive file is valid: %s (%llu bytes)", path, file_size.QuadPart);
        return true;
    }

    scoped_user_hive() {
        // Ensure the local working directory exists and create a unique temp file
        ensure_local_path();

        debug_log(L"INFO: Initializing scoped_user_hive");

        // Validate the source hive before copying
        if (!validate_hive_file(STEAM_KIOSK_HIVE)) {
            debug_log(L"ERROR: Source hive validation failed");
            return;
        }

        // Create a unique temp name in the repo-local `local` directory to avoid
        // collisions with other runs/processes. GetTempFileNameW will create the
        // file — we'll overwrite it with a copy of the hive.
        if (GetTempFileNameW(LOCAL_PATH, L"KHI", 0, temp_hive) == 0) {
            debug_log(L"ERROR: Failed to generate temporary hive filename");
            return;
        }

        debug_log(L"INFO: Created temporary hive path: %s", temp_hive);

        // Copy the live hive into the temp location. Overwrite any existing temp.
        if (!CopyFileW(STEAM_KIOSK_HIVE, temp_hive, FALSE)) {
            debug_log(L"ERROR: Failed to copy hive to temporary location. LastError: %lu",
                      GetLastError());
            DeleteFileW(temp_hive);
            return;
        }

        // Validate the copied hive
        if (!validate_hive_file(temp_hive)) {
            debug_log(L"ERROR: Temporary hive copy validation failed - source may be corrupted");
            DeleteFileW(temp_hive);
            return;
        }

        debug_log(L"INFO: Temporary hive copy validated successfully");

        if (RegLoadKeyW(HKEY_USERS, hive_name, temp_hive) == ERROR_SUCCESS) {
            loaded = true;
            debug_log(L"INFO: Hive loaded successfully into registry");
        } else {
            debug_log(L"ERROR: Failed to load hive into registry. LastError: %lu", GetLastError());
            DeleteFileW(temp_hive);
        }
    }

    ~scoped_user_hive() {
        if (loaded) {
            debug_log(L"INFO: Unloading hive from registry");
            RegUnLoadKeyW(HKEY_USERS, hive_name);
            
            // CRITICAL: Copy the modified temp hive back to the original NTUSER.DAT
            // so changes persist between application runs
            if (!CopyFileW(temp_hive, STEAM_KIOSK_HIVE, FALSE)) {
                debug_log(L"ERROR: Failed to copy modified hive back to NTUSER.DAT. LastError: %lu", 
                          GetLastError());
            } else {
                debug_log(L"INFO: Modified hive successfully copied back to NTUSER.DAT");
            }
            
            if (!DeleteFileW(temp_hive)) {
                debug_log(L"WARNING: Failed to delete temporary hive file: %s", temp_hive);
            } else {
                debug_log(L"INFO: Temporary hive file deleted");
            }
        }
    }

    bool ok() const {
        return loaded;
    }
};

// ========================================
// Misc Helpers
// ========================================

inline bool delete_directory_recursive(const wchar_t* path) {
    wchar_t search_path[MAX_PATH];
    swprintf_s(search_path, L"%s\\*", path);

    WIN32_FIND_DATAW fd;
    HANDLE h_find = FindFirstFileW(search_path, &fd);

    if (h_find == INVALID_HANDLE_VALUE) {
        debug_log(L"WARNING: Could not find files in directory: %s. LastError: %lu", 
                  path, GetLastError());
        return false;
    }

    int deleted_files = 0;
    int deleted_dirs = 0;
    int failed_items = 0;

    do {
        if (wcscmp(fd.cFileName, L".") == 0 ||
            wcscmp(fd.cFileName, L"..") == 0)
            continue;

        wchar_t full_path[MAX_PATH];
        swprintf_s(full_path, L"%s\\%s", path, fd.cFileName);

        // Clear attributes (readonly/system)
        SetFileAttributesW(full_path, FILE_ATTRIBUTE_NORMAL);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!delete_directory_recursive(full_path)) {
                failed_items++;
                debug_log(L"WARNING: Failed to delete subdirectory: %s", full_path);
            } else {
                deleted_dirs++;
            }
        } else {
            if (!DeleteFileW(full_path)) {
                failed_items++;
                debug_log(L"WARNING: Failed to delete file: %s. LastError: %lu", 
                          full_path, GetLastError());
            } else {
                deleted_files++;
            }
        }
    } while (FindNextFileW(h_find, &fd));

    FindClose(h_find);

    debug_log(L"INFO: Directory cleanup stats - Deleted files: %d, Deleted dirs: %d, Failed: %d",
              deleted_files, deleted_dirs, failed_items);

    // Finally remove the now-empty directory
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    if (!RemoveDirectoryW(path)) {
        debug_log(L"WARNING: Failed to remove directory: %s. LastError: %lu",
                  path, GetLastError());
        return false;
    }

    return true;
}

inline bool terminate_processes_for_user(const wchar_t* username) {
    debug_log(L"INFO: Terminating all processes for user: %s", username);

    int terminated_count = 0;
    int attempts = 0;
    const int MAX_ATTEMPTS = 3;

    // Multiple passes to ensure all processes are killed
    while (attempts < MAX_ATTEMPTS) {
        attempts++;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            debug_log(L"WARNING: Failed to create process snapshot (attempt %d/%d)", attempts, MAX_ATTEMPTS);
            Sleep(100);
            continue;
        }

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (!Process32FirstW(snap, &pe)) {
            CloseHandle(snap);
            debug_log(L"WARNING: Failed to get first process (attempt %d/%d)", attempts, MAX_ATTEMPTS);
            Sleep(100);
            continue;
        }

        int pass_terminated = 0;
        do {
            HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                                      FALSE, pe.th32ProcessID);
            if (!proc)
                continue;

            HANDLE token;
            if (OpenProcessToken(proc, TOKEN_QUERY, &token)) {
                DWORD size = 0;
                GetTokenInformation(token, TokenUser, nullptr, 0, &size);

                if (size) {
                    BYTE buf[512];
                    if (size <= sizeof(buf) &&
                        GetTokenInformation(token, TokenUser, buf, size, &size)) {
                        TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf);

                        wchar_t name[128], domain[128];
                        DWORD nlen = 128, dlen = 128;
                        SID_NAME_USE use;

                        if (LookupAccountSidW(nullptr, tu->User.Sid, name, &nlen,
                                              domain, &dlen, &use)) {
                            if (_wcsicmp(name, username) == 0) {
                                if (TerminateProcess(proc, 1)) {
                                    pass_terminated++;
                                    terminated_count++;
                                    debug_log(L"INFO: Terminated process PID %lu", pe.th32ProcessID);
                                }
                            }
                        }
                    }
                }
                CloseHandle(token);
            }
            CloseHandle(proc);
        } while (Process32NextW(snap, &pe));

        CloseHandle(snap);

        if (pass_terminated == 0) {
            debug_log(L"INFO: No more processes found for user (attempt %d/%d)", attempts, MAX_ATTEMPTS);
            break;
        }

        debug_log(L"INFO: Pass %d: Terminated %d processes", attempts, pass_terminated);
        Sleep(200);  // Give processes time to terminate
    }

    debug_log(L"SUCCESS: Process termination complete. Total terminated: %d", terminated_count);
    return true;
}

// ========================================
// User Account Disabling
// ========================================
inline bool disable_kiosk_user_account() {
    debug_log(L"INFO: Disabling kiosk user account");

    USER_INFO_3* pui = nullptr;
    DWORD dw_error = 0;

    // Retrieve current user info - NetUserGetInfo allocates the buffer
    NET_API_STATUS status = NetUserGetInfo(nullptr, STEAM_KIOSK_USER, 3,
                                           reinterpret_cast<LPBYTE*>(&pui));
    if (status != NERR_Success) {
        debug_log(L"ERROR: Failed to get user info. Status: %lu", status);
        return false;
    }

    if (!pui) {
        debug_log(L"ERROR: NetUserGetInfo returned null pointer");
        return false;
    }

    // Set the disabled flag
    pui->usri3_flags |= UF_ACCOUNTDISABLE;

    // Update the user with disabled flag
    status = NetUserSetInfo(nullptr, STEAM_KIOSK_USER, 3,
                           reinterpret_cast<LPBYTE>(pui), &dw_error);

    if (status != NERR_Success) {
        debug_log(L"ERROR: Failed to disable user account. NetAPI Status: %lu, ParamError: %lu",
                  status, dw_error);
        NetApiBufferFree(pui);
        return false;
    }

    NetApiBufferFree(pui);
    debug_log(L"SUCCESS: User account disabled");
    return true;
}

// ========================================
// NTUSER.DAT Helpers
// ========================================
inline bool ntuserdat_backup() {
    ensure_local_path();

    debug_log(L"INFO: Starting NTUSER.DAT backup");

    // Do not overwrite an existing baseline
    if (GetFileAttributesW(NTUSER_BACKUP_PATH) != INVALID_FILE_ATTRIBUTES) {
        debug_log(L"INFO: Backup already exists, skipping backup creation");
        return true;
    }

    if (!CopyFileW(STEAM_KIOSK_HIVE, NTUSER_BACKUP_PATH, TRUE)) {
        debug_log(L"ERROR: Failed to create backup. LastError: %lu", GetLastError());
        return false;
    }

    debug_log(L"SUCCESS: Profile backup created successfully: %s", NTUSER_BACKUP_PATH);
    return true;
}

inline bool ntuserdat_restore() {
    debug_log(L"INFO: Starting NTUSER.DAT restore");

    // Backup must exist
    if (GetFileAttributesW(NTUSER_BACKUP_PATH) == INVALID_FILE_ATTRIBUTES) {
        debug_log(L"ERROR: Backup file not found: %s", NTUSER_BACKUP_PATH);
        return false;
    }

    // Live hive must exist
    if (GetFileAttributesW(STEAM_KIOSK_HIVE) == INVALID_FILE_ATTRIBUTES) {
        debug_log(L"ERROR: Live hive not found: %s", STEAM_KIOSK_HIVE);
        return false;
    }

    // Best effort: remove attributes that might block overwrite
    SetFileAttributesW(STEAM_KIOSK_HIVE, FILE_ATTRIBUTE_NORMAL);

    if (!CopyFileW(NTUSER_BACKUP_PATH, STEAM_KIOSK_HIVE, FALSE)) {
        debug_log(L"ERROR: Failed to restore backup. LastError: %lu", GetLastError());
        return false;
    }

    debug_log(L"SUCCESS: Profile restored from backup");
    return true;
}

// ========================================
// Privileges
// ========================================
inline bool system_privilege_enable(HANDLE h_token, LPCWSTR privilege, BOOL enable) {
    TOKEN_PRIVILEGES tp{};
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        debug_log(L"ERROR: Failed to lookup privilege: %s", privilege);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        debug_log(L"ERROR: Failed to adjust token privileges for: %s", privilege);
        return false;
    }

    if (GetLastError() != ERROR_SUCCESS) {
        debug_log(L"ERROR: Privilege adjustment error for: %s", privilege);
        return false;
    }

    debug_log(L"INFO: %s privilege %s successfully", privilege, enable ? L"enabled" : L"disabled");
    return true;
}

// ========================================
// User Management
// ========================================
inline bool kiosk_user_exists() {
    USER_INFO_0* buf = nullptr;
    DWORD entries_read, total_entries;
    auto res = NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT,
                           reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
                           &entries_read, &total_entries, nullptr);
    if (res != NERR_Success) {
        debug_log(L"ERROR: Failed to enumerate users. Status: %lu", res);
        return false;
    }

    for (DWORD i = 0; i < entries_read; i++) {
        if (_wcsicmp(buf[i].usri0_name, STEAM_KIOSK_USER) == 0) {
            debug_log(L"INFO: Kiosk user already exists: %s", STEAM_KIOSK_USER);
            NetApiBufferFree(buf);
            return true;
        }
    }

    if (buf) {
        NetApiBufferFree(buf);
    }

    debug_log(L"INFO: Kiosk user does not exist: %s", STEAM_KIOSK_USER);
    return false;
}

inline bool kiosk_user_create() {
    USER_INFO_1 ui{};
    DWORD dw_error = 0;

    ui.usri1_name     = const_cast<LPWSTR>(STEAM_KIOSK_USER);
    ui.usri1_password = const_cast<LPWSTR>(STEAM_KIOSK_PASS);
    ui.usri1_priv     = USER_PRIV_USER;
    ui.usri1_flags    = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

    if (NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &dw_error) == NERR_Success) {
        debug_log(L"SUCCESS: Kiosk user created: %s", STEAM_KIOSK_USER);
        return true;
    }

    debug_log(L"ERROR: Failed to create kiosk user. Status: %lu", dw_error);
    return false;
}

inline void kiosk_user_destroy() {
    if (NetUserDel(nullptr, STEAM_KIOSK_USER) == NERR_Success) {
        debug_log(L"SUCCESS: Kiosk user deleted: %s", STEAM_KIOSK_USER);
    } else {
        debug_log(L"ERROR: Failed to delete kiosk user: %s", STEAM_KIOSK_USER);
    }
}

// ========================================
// Kiosk Profile
// ========================================
inline int kiosk_profile_exists() {
    // Return codes:
    // 0 = profile exists and hive is readable
    // 1 = profile missing (NTUSER.DAT not present)
    // 3 = profile present but hive could not be loaded (corrupt/unreadable)

    if (GetFileAttributesW(STEAM_KIOSK_HIVE) == INVALID_FILE_ATTRIBUTES) {
        debug_log(L"INFO: Kiosk profile does not exist yet");
        return 1;
    }

    // Try loading the hive via a temporary copy while holding the required
    // privileges. This avoids loading the live NTUSER.DAT directly which
    // can corrupt the user's profile if the system already has it loaded.
    scoped_privileges privs { SE_RESTORE_NAME, SE_BACKUP_NAME };
    scoped_user_hive hive;

    if (!hive.ok()) {
        debug_log(L"ERROR: Kiosk profile is corrupted or unreadable. Cannot load hive.");
        return 3;
    }

    debug_log(L"SUCCESS: Kiosk profile exists and is readable");
    return 0;
}

// ========================================
// Autologin
// ========================================
inline void autologin_enable() {
    debug_log(L"INFO: Enabling autologin");

    HKEY h_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) != ERROR_SUCCESS) {
        debug_log(L"ERROR: Failed to open Winlogon registry key");
        return;
    }

    RegSetValueExW(h_key, L"AutoAdminLogon", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(L"1"),
                   sizeof(L"1"));
    RegSetValueExW(h_key, L"DefaultUserName", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(STEAM_KIOSK_USER),
                   static_cast<DWORD>((wcslen(STEAM_KIOSK_USER) + 1) * sizeof(wchar_t)));
    RegSetValueExW(h_key, L"DefaultPassword", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(STEAM_KIOSK_PASS),
                   static_cast<DWORD>((wcslen(STEAM_KIOSK_PASS) + 1) * sizeof(wchar_t)));
    RegSetValueExW(h_key, L"DefaultDomainName", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(L"."),
                   sizeof(L"."));

    RegFlushKey(h_key);
    RegCloseKey(h_key);
    debug_log(L"SUCCESS: Autologin enabled");
}

inline void autologin_disable() {
    debug_log(L"INFO: Disabling autologin");

    HKEY h_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS) {
        RegSetValueExW(h_key, L"AutoAdminLogon", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(L"0"),
                       sizeof(L"0"));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
        debug_log(L"SUCCESS: Autologin disabled");
    } else {
        debug_log(L"ERROR: Failed to open Winlogon registry key");
    }
}

inline bool autologin_status() {
    HKEY h_key;
    wchar_t buf[512]{};
    DWORD type;
    DWORD size;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_READ, &h_key) != ERROR_SUCCESS)
        return false;

    size = sizeof(buf);
    if (RegQueryValueExW(h_key, L"AutoAdminLogon", nullptr, &type,
                         (BYTE*)buf, &size) != ERROR_SUCCESS ||
        type != REG_SZ || wcscmp(buf, L"1") != 0) {
        RegCloseKey(h_key);
        return false;
    }

    size = sizeof(buf);
    if (RegQueryValueExW(h_key, L"DefaultUserName", nullptr, &type,
                         (BYTE*)buf, &size) != ERROR_SUCCESS ||
        type != REG_SZ || wcscmp(buf, STEAM_KIOSK_USER) != 0) {
        RegCloseKey(h_key);
        return false;
    }

    RegCloseKey(h_key);
    return true;
}

// ========================================
// Other Users Prompt
// ========================================
bool users_prompt_helper(bool enable) {
    debug_log(L"INFO: %s users prompt", enable ? L"Enabling" : L"Disabling");

    HKEY h_key;
    DWORD value = enable ? 1 : 0;
    DWORD disposition = 0;

    // Use RegCreateKeyExW to ensure path exists (needed if key doesn't exist yet)
    LONG rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                              L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                              0, nullptr, REG_OPTION_NON_VOLATILE,
                              KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &h_key, &disposition);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"ERROR: Failed to create/open Policies registry key. Status: %lu", rc);
        return false;
    }

    debug_log(L"VERBOSE: Users prompt registry path %s (disposition: %lu)",
              (disposition == REG_CREATED_NEW_KEY) ? L"CREATED" : L"OPENED", disposition);

    rc = RegSetValueExW(h_key, L"dontdisplaylastusername", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&value), sizeof(value));

    debug_log(L"VERBOSE: RegSetValueExW returned status: %lu", rc);

    if (rc == ERROR_SUCCESS) {
        // Verify the write by reading back
        DWORD verify_value = 0;
        DWORD verify_size = sizeof(verify_value);
        DWORD verify_type = 0;

        LONG verify_rc = RegQueryValueExW(h_key, L"dontdisplaylastusername", nullptr, &verify_type,
                                          reinterpret_cast<BYTE*>(&verify_value), &verify_size);

        if (verify_rc == ERROR_SUCCESS && verify_type == REG_DWORD) {
            debug_log(L"VERBOSE: Users prompt value verified - Read back: %lu (expected: %lu)",
                      verify_value, value);
        }
    }

    RegFlushKey(h_key);
    RegCloseKey(h_key);

    if (rc == ERROR_SUCCESS) {
        debug_log(L"SUCCESS: Users prompt %s", enable ? L"enabled" : L"disabled");
    } else {
        debug_log(L"ERROR: Failed to set users prompt. Status: %lu", rc);
    }

    return rc == ERROR_SUCCESS;
}

inline bool users_prompt_status() {
    HKEY h_key;
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;

    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                            0, KEY_QUERY_VALUE, &h_key);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Cannot open Policies registry key for status check. Status: %lu", rc);
        return false;
    }

    rc = RegQueryValueExW(h_key, L"dontdisplaylastusername", nullptr, &type,
                          reinterpret_cast<BYTE*>(&value), &size);

    RegCloseKey(h_key);

    bool result = rc == ERROR_SUCCESS && type == REG_DWORD && value == 1;
    
    if (rc == ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Users prompt status query - Value: %lu, Type: %lu (REG_DWORD=%u), Result: %s",
                  value, type, REG_DWORD, result ? L"TRUE" : L"FALSE");
    } else {
        debug_log(L"VERBOSE: Failed to query users prompt value. Status: %lu", rc);
    }

    return result;
}

inline void users_prompt_enable() {
    debug_log(L"VERBOSE: User clicked Enable Users Prompt button");
    users_prompt_helper(true);
}

inline void users_prompt_disable() {
    debug_log(L"VERBOSE: User clicked Disable Users Prompt button");
    users_prompt_helper(false);
}

// ========================================
// Kiosk Shell
// ========================================
inline bool kiosk_set_shell(LPCWSTR shell_cmd) {
    debug_log(L"INFO: Setting kiosk shell to: %s", shell_cmd);

    scoped_privileges privs { SE_BACKUP_NAME, SE_RESTORE_NAME };
    scoped_user_hive hive;

    if (!hive.ok()) {
        debug_log(L"ERROR: Cannot access user hive to set shell");
        return false;
    }

    // First, ensure the registry path exists - create it if needed
    HKEY path_key;
    LONG rc = RegCreateKeyExW(HKEY_USERS,
                              L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                              0, nullptr, REG_OPTION_NON_VOLATILE,
                              KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &path_key, nullptr);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"ERROR: Failed to create/open Winlogon path. Status: %lu", rc);
        return false;
    }

    debug_log(L"VERBOSE: Winlogon registry path created/opened successfully");

    DWORD size = (DWORD)((wcslen(shell_cmd) + 1) * sizeof(wchar_t));
    debug_log(L"VERBOSE: Writing shell value - Size: %lu bytes, Command length: %lu chars", 
              size, wcslen(shell_cmd));

    rc = RegSetValueExW(path_key, L"Shell", 0, REG_SZ,
                        reinterpret_cast<const BYTE*>(shell_cmd), size);

    debug_log(L"VERBOSE: RegSetValueExW returned status: %lu", rc);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"ERROR: Failed to set shell value in registry. Status: %lu", rc);
        RegCloseKey(path_key);
        return false;
    }

    // Verify the value was written by reading it back immediately
    wchar_t verify_shell[512]{};
    DWORD verify_size = sizeof(verify_shell);
    DWORD verify_type = 0;

    debug_log(L"VERBOSE: Attempting to verify written shell value...");

    rc = RegQueryValueExW(path_key, L"Shell", nullptr, &verify_type,
                         reinterpret_cast<BYTE*>(verify_shell), &verify_size);

    debug_log(L"VERBOSE: RegQueryValueExW verification returned status: %lu", rc);
    debug_log(L"VERBOSE: Type: %lu (should be %lu for REG_SZ)", verify_type, REG_SZ);

    if (rc == ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Read back shell value: %s", verify_shell);
        debug_log(L"VERBOSE: Verification size: %lu bytes", verify_size);
    }

    // Flush to ensure written to disk
    RegFlushKey(path_key);
    debug_log(L"VERBOSE: RegFlushKey called");

    RegCloseKey(path_key);

    if (rc == ERROR_SUCCESS && verify_type == REG_SZ && wcscmp(verify_shell, shell_cmd) == 0) {
        debug_log(L"SUCCESS: Shell set and verified: %s", shell_cmd);
        return true;
    } else {
        debug_log(L"ERROR: Shell value verification failed!");
        debug_log(L"  - QueryStatus: %lu", rc);
        debug_log(L"  - Type match: %s", (verify_type == REG_SZ) ? L"YES" : L"NO");
        if (rc == ERROR_SUCCESS) {
            debug_log(L"  - String match: %s", (wcscmp(verify_shell, shell_cmd) == 0) ? L"YES" : L"NO");
            debug_log(L"  - Expected: %s", shell_cmd);
            debug_log(L"  - Got:      %s", verify_shell);
        }
        return false;
    }
}

inline void kiosk_shell_bigpicture() {
    debug_log(L"VERBOSE: User clicked Big Picture shell button");
    if (kiosk_set_shell(BIG_PICTURE_EXEC)) {
        debug_log(L"SUCCESS: Big Picture shell enabled");
    } else {
        debug_log(L"ERROR: Failed to enable Big Picture shell");
    }
}

inline void kiosk_shell_explorer() {
    debug_log(L"VERBOSE: User clicked Explorer shell button");
    if (kiosk_set_shell(L"explorer.exe")) {
        debug_log(L"SUCCESS: Explorer shell enabled");
    } else {
        debug_log(L"ERROR: Failed to enable Explorer shell");
    }
}

inline bool kiosk_shell_status() {
    scoped_privileges privs { SE_BACKUP_NAME, SE_RESTORE_NAME };
    scoped_user_hive hive;

    if (!hive.ok()) {
        debug_log(L"WARNING: Cannot access hive to check shell status");
        return false;
    }

    HKEY key;
    LONG rc = RegOpenKeyExW(HKEY_USERS,
                            L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                            0, KEY_QUERY_VALUE, &key);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Cannot open Winlogon key for status check. Status: %lu", rc);
        return false;
    }

    wchar_t shell[512]{};
    DWORD size = sizeof(shell);
    DWORD type = 0;

    debug_log(L"VERBOSE: About to query Shell value from registry...");

    rc = RegQueryValueExW(key, L"Shell", nullptr, &type,
                         reinterpret_cast<BYTE*>(shell), &size);

    debug_log(L"VERBOSE: RegQueryValueExW returned status: %lu, Type: %lu, Size: %lu", rc, type, size);

    if (rc == ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Shell value read successfully: %s", shell);
    } else {
        debug_log(L"VERBOSE: Failed to read Shell value. Status: %lu", rc);
    }

    RegCloseKey(key);

    if (rc != ERROR_SUCCESS) {
        debug_log(L"VERBOSE: Shell value not found or error reading - returning false");
        return false;
    }

    bool is_bigpicture = (wcscmp(shell, BIG_PICTURE_EXEC) == 0);
    debug_log(L"INFO: Shell status check - Value: '%s', IsBigPicture: %d", 
              shell, is_bigpicture ? 1 : 0);
    
    return is_bigpicture;
}

// ========================================
// Session Helpers
// ========================================
inline void logoff_user() {
    debug_log(L"INFO: Initiating user logoff");
    ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0);
}

inline void restart_user() {
    debug_log(L"INFO: Initiating system restart");
    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
}

// ========================================
// UI Helpers
// ========================================
inline void update_ui() {
    debug_log(L"VERBOSE: update_ui() called - refreshing all UI elements");
    
    BOOL autologin_checked = autologin_status() ? BST_CHECKED : BST_UNCHECKED;
    debug_log(L"VERBOSE: autologin_status() returned: %d", autologin_checked);
    SendMessageW(g_hwnd_autologin, BM_SETCHECK, autologin_checked, 0);
    
    BOOL shell_status = kiosk_shell_status();
    BOOL shell_checked = shell_status ? BST_CHECKED : BST_UNCHECKED;
    debug_log(L"VERBOSE: kiosk_shell_status() returned: %d, setting checkbox to: %d", shell_status, shell_checked);
    SendMessageW(g_hwnd_shell, BM_SETCHECK, shell_checked, 0);
    
    BOOL users_prompt_checked = users_prompt_status() ? BST_CHECKED : BST_UNCHECKED;
    debug_log(L"VERBOSE: users_prompt_status() returned: %d, setting checkbox to: %d", users_prompt_status(), users_prompt_checked);
    SendMessageW(g_hwnd_users_prompt, BM_SETCHECK, users_prompt_checked, 0);
    
    debug_log(L"VERBOSE: update_ui() complete");
}

inline void prompt_first_login() {
    wchar_t msg[512];
    swprintf_s(msg, L"Kiosk user created:\n\n"
                    L"Username: %s\n"
                    L"Password: %s\n\n"
                    L"After closing this message box, the login screen will appear.\n"
                    L"Login using the details provided above and wait for initialisation to complete.\n"
                    L"Then logout, and log back into your personal user account to return to this helper.",
                STEAM_KIOSK_USER, STEAM_KIOSK_PASS);

    debug_log(L"INFO: Displaying first login prompt");
    MessageBoxW(nullptr, msg, L"Steam Kiosk Setup", MB_OK | MB_ICONINFORMATION);
}

inline bool prompt_corrupt_profile() {
    wchar_t msg[256];
    swprintf_s(msg, L"NTUSER.DAT for %s is corrupted and unreadable!\n\n"
                    L"Certain functionality may not work correctly.\n"
                    L"Please destroy the user profile and attempt running again.\n\n"
                    L"Attempt to restore from backup?",
                    STEAM_KIOSK_USER);

    debug_log(L"ERROR: Displaying corrupt profile prompt");
    int result = MessageBoxW(nullptr, msg, L"Steam Kiosk Setup",
                             MB_YESNO | MB_ICONERROR);

    return result == IDYES;  // true if user clicked Yes, false if No
}

inline void switch_to_other_user_screen() {
    debug_log(L"INFO: Switching to other user screen");
    autologin_disable();
    WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, FALSE);
}

// ========================================
// Delete User Profile
// ========================================
inline bool delete_kiosk_user_profile() {
    debug_log(L"INFO: Deleting kiosk user profile: %s", STEAM_KIOSK_PROFILE_DIR);

    DWORD attrs = GetFileAttributesW(STEAM_KIOSK_PROFILE_DIR);

    // Nothing to do
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        debug_log(L"INFO: Profile directory does not exist");
        return true;
    }

    // Must be a directory
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        debug_log(L"ERROR: Profile path is not a directory");
        return false;
    }

    int delete_attempts = 0;
    const int MAX_DELETE_ATTEMPTS = 3;

    while (delete_attempts < MAX_DELETE_ATTEMPTS) {
        delete_attempts++;
        if (delete_directory_recursive(STEAM_KIOSK_PROFILE_DIR)) {
            debug_log(L"SUCCESS: Profile directory deleted (attempt %d)", delete_attempts);
            return true;
        }
        debug_log(L"WARNING: Failed to delete profile directory (attempt %d/%d)", 
                  delete_attempts, MAX_DELETE_ATTEMPTS);
        Sleep(500);  // Wait before retry
    }

    debug_log(L"ERROR: Failed to delete profile directory after %d attempts", MAX_DELETE_ATTEMPTS);
    return false;
}

inline bool destroy_kiosk_user_completely() {
    debug_log(L"INFO: Starting complete kiosk user destruction");

    // Ensure we have required privileges
    scoped_privileges privs { SE_BACKUP_NAME, SE_RESTORE_NAME };

    // 1. Disable autologin first
    autologin_disable();

    // 2. Disable the user account (prevents future login)
    // Continue even if this fails - it's not critical
    if (!disable_kiosk_user_account()) {
        debug_log(L"WARNING: User account disabling failed, but continuing with deletion");
    }

    // 3. Kill any remaining kiosk processes (multiple passes)
    terminate_processes_for_user(STEAM_KIOSK_USER);
    Sleep(1000);

    // 4. Second pass to catch any lingering processes
    terminate_processes_for_user(STEAM_KIOSK_USER);
    Sleep(500);

    // 5. Delete profile directory (NTUSER.DAT must not be loaded)
    if (!delete_kiosk_user_profile()) {
        debug_log(L"ERROR: Failed to delete profile directory during destruction");
        // Don't return false yet - try to delete user anyway
    }

    // 6. Delete the user account
    kiosk_user_destroy();

    debug_log(L"SUCCESS: Complete kiosk user destruction finished");
    return true;
}

// ========================================
// Main Window Procedure
// ========================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        if ((HWND)lParam == g_hwnd_autologin)
            autologin_status() ? autologin_disable() : autologin_enable();
        else if ((HWND)lParam == g_hwnd_shell)
            kiosk_shell_status() ? kiosk_shell_explorer() : kiosk_shell_bigpicture();
        else if ((HWND)lParam == g_hwnd_users_prompt)
            users_prompt_status() ? users_prompt_disable() : users_prompt_enable();
        else if ((HWND)lParam == g_hwnd_logoff)
            logoff_user();
        else if ((HWND)lParam == g_hwnd_restart)
            restart_user();
        else if ((HWND)lParam == g_hwnd_delete_user) {
            if (MessageBoxW(hwnd, L"Are you sure you want to delete the Steam Kiosk user?",
                            L"Confirm Delete", MB_YESNO | MB_ICONWARNING) == IDYES) {
                if (destroy_kiosk_user_completely()) {
                    debug_log(L"SUCCESS: User confirmed deletion - cleaning up");
                    MessageBoxW(hwnd, L"Steam Kiosk user and profile deleted successfully.",
                                L"Deleted", MB_OK | MB_ICONINFORMATION);
                    ExitProcess(0);
                } else {
                    debug_log(L"ERROR: Deletion failed after user confirmation");
                    MessageBoxW(hwnd, L"Failed to delete Steam Kiosk user and/or profile.",
                                L"Error", MB_OK | MB_ICONERROR);
                }
                update_ui();
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        update_ui();
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ========================================
// Kiosk Setup
// ========================================
void kiosk_setup_if_needed() {
    debug_log(L"INFO: Starting kiosk setup check");

    if (!kiosk_user_exists()) {
        debug_log(L"INFO: Kiosk user does not exist, creating...");
        if (!kiosk_user_create()) {
            debug_log(L"FATAL: Failed to create Steam Kiosk user");
            MessageBoxW(nullptr, L"Failed to create Steam Kiosk user.", L"Error", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
    }

    int profile_status = kiosk_profile_exists();
    if (profile_status == 1) {
        // First login needed
        debug_log(L"INFO: Profile does not exist, first login needed");
        prompt_first_login();
        users_prompt_enable();
        switch_to_other_user_screen();
        Sleep(5000);  // Give some time for the user to switch
        users_prompt_disable();
        Sleep(20000);
        MessageBoxW(nullptr, L"Please press OK to continue and proceed to backing up the profile.",
                    L"Profile Backup", MB_OK | MB_ICONINFORMATION);
        Sleep(1000);
        if (ntuserdat_backup()) {
            debug_log(L"SUCCESS: Profile backed up successfully");
            MessageBoxW(nullptr, L"Profile backup created successfully.",
                        L"Backup Created", MB_OK | MB_ICONINFORMATION);
        } else {
            debug_log(L"ERROR: Failed to backup profile");
            MessageBoxW(nullptr, L"Failed to create profile backup.",
                        L"Backup Failed", MB_OK | MB_ICONERROR);
        }
    } else if (profile_status == 3) {
        debug_log(L"ERROR: Profile is corrupted, prompting user for restore");
        if (prompt_corrupt_profile()) {
            if (ntuserdat_restore()) {
                debug_log(L"SUCCESS: Profile restored from backup");
                MessageBoxW(nullptr, L"Profile restored from backup. Please restart the application.",
                            L"Profile Restored", MB_OK | MB_ICONINFORMATION);
            } else {
                debug_log(L"ERROR: Failed to restore profile from backup");
                MessageBoxW(nullptr, L"Failed to restore profile from backup. Please restart and try again.\n"
                                     L"If it continues, delete NTUSER.DAT and try again.\n"
                                     L"If all else fails, delete the user and folder and try again.",
                            L"Profile Restore Failed", MB_OK | MB_ICONERROR);
            }
            ExitProcess(1);
        } else {
            debug_log(L"INFO: User declined profile restore");
        }
    } else {
        debug_log(L"SUCCESS: Profile exists and is healthy");
    }
}

// ========================================
// Main Entry
// ========================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int) {
    debug_log(L"INFO: Application starting");

    // Create or open a named mutex to ensure single instance
    g_single_instance_mutex = CreateMutexW(nullptr, TRUE, L"Global\\SteamKioskHelper_Mutex");
    if (!g_single_instance_mutex) {
        debug_log(L"ERROR: Failed to create single instance mutex");
        MessageBoxW(nullptr, L"Failed to initialize application.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Check if another instance is already running
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        debug_log(L"WARNING: Another instance of the application is already running. Exiting.");
        MessageBoxW(nullptr, 
                    L"Steam Kiosk Helper is already running.\n\n"
                    L"Only one instance can run at a time.",
                    L"Application Already Running", 
                    MB_OK | MB_ICONWARNING);
        ReleaseMutex(g_single_instance_mutex);
        CloseHandle(g_single_instance_mutex);
        return 1;
    }

    debug_log(L"INFO: Single instance lock acquired successfully");
    kiosk_setup_if_needed();

    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"SteamKioskHelper";
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowW(wc.lpszClassName, L"Steam Kiosk Helper",
                              WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              MAIN_WINDOW_WIDTH, MAIN_WINDOW_HEIGHT,
                              nullptr, nullptr, hInst, nullptr);

    // Title
    g_hwnd_title = CreateWindowW(L"STATIC", L"Steam Kiosk Helper",
                                 WS_CHILD | WS_VISIBLE | SS_CENTER,
                                 0, 10, MAIN_WINDOW_WIDTH, 30,
                                 hwnd, nullptr, hInst, nullptr);

    HFONT h_font = CreateFontW(FONT_SIZE, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");

    SendMessageW(g_hwnd_title, WM_SETFONT, (WPARAM)h_font, TRUE);

    // Buttons / Checkboxes 2x2 grid
    // 20+112+12+112+12+112+20 
    // ((400−(20×2))−(12×2))×1/3
    g_hwnd_autologin = CreateWindowW(L"BUTTON", L"Autologin",
                                     WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                     20, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                                     hwnd, nullptr, hInst, nullptr);

    g_hwnd_shell = CreateWindowW(L"BUTTON", L"Big-Picture Shell",
                                 WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                 144, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                                 hwnd, nullptr, hInst, nullptr);

    g_hwnd_users_prompt = CreateWindowW(L"BUTTON", L"User Prompt",
                                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                        268, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                                        hwnd, nullptr, hInst, nullptr);

    g_hwnd_logoff = CreateWindowW(L"BUTTON", L"Log Off",
                                  WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                  50, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                                  hwnd, nullptr, hInst, nullptr);

    g_hwnd_restart = CreateWindowW(L"BUTTON", L"Restart",
                                   WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                   220, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                                   hwnd, nullptr, hInst, nullptr);

    // Delete User button (bottom middle)
    g_hwnd_delete_user = CreateWindowW(L"BUTTON", L"Delete User",
                                       WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                       (MAIN_WINDOW_WIDTH - BUTTON_WIDTH) / 2,
                                       180,
                                       BUTTON_WIDTH, BUTTON_HEIGHT,
                                       hwnd, nullptr, hInst, nullptr);

    SendMessageW(g_hwnd_autologin, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(g_hwnd_shell, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(g_hwnd_users_prompt, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(g_hwnd_logoff, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(g_hwnd_restart, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(g_hwnd_delete_user, WM_SETFONT, (WPARAM)h_font, TRUE);

    ShowWindow(hwnd, SW_SHOW);
    update_ui();

    debug_log(L"INFO: Main window created and displayed");

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // Clean up single instance mutex
    if (g_single_instance_mutex) {
        ReleaseMutex(g_single_instance_mutex);
        CloseHandle(g_single_instance_mutex);
        debug_log(L"INFO: Single instance mutex released");
    }

    debug_log(L"INFO: Application exiting");
    return 0;
}
