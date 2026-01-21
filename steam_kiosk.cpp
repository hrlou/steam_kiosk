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

    scoped_user_hive() {
        // Ensure the local working directory exists and create a unique temp file
        ensure_local_path();

        // Create a unique temp name in the repo-local `local` directory to avoid
        // collisions with other runs/processes. GetTempFileNameW will create the
        // file — we'll overwrite it with a copy of the hive.
        if (GetTempFileNameW(LOCAL_PATH, L"KHI", 0, temp_hive) == 0)
            return;

        // Copy the live hive into the temp location. Overwrite any existing temp.
        if (!CopyFileW(STEAM_KIOSK_HIVE, temp_hive, FALSE)) {
            // remove the temp file created by GetTempFileNameW
            DeleteFileW(temp_hive);
            return;
        }

        if (RegLoadKeyW(HKEY_USERS, hive_name, temp_hive) == ERROR_SUCCESS)
            loaded = true;
    }

    ~scoped_user_hive() {
        if (loaded) {
            RegUnLoadKeyW(HKEY_USERS, hive_name);
            DeleteFileW(temp_hive);
        }
    }

    bool ok() const { return loaded; }
};

// ========================================
// Misc Helpers
// ========================================

inline bool delete_directory_recursive(const wchar_t* path)
{
    wchar_t search_path[MAX_PATH];
    swprintf_s(search_path, L"%s\\*", path);

    WIN32_FIND_DATAW fd;
    HANDLE h_find = FindFirstFileW(search_path, &fd);

    if (h_find == INVALID_HANDLE_VALUE)
        return false;

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
                FindClose(h_find);
                return false;
            }
        } else {
            if (!DeleteFileW(full_path)) {
                FindClose(h_find);
                return false;
            }
        }
    } while (FindNextFileW(h_find, &fd));

    FindClose(h_find);

    // Finally remove the now-empty directory
    SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryW(path) != FALSE;
}

inline bool terminate_processes_for_user(const wchar_t* username)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (!Process32FirstW(snap, &pe)) {
        CloseHandle(snap);
        return false;
    }

    do {
        HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
                                  PROCESS_TERMINATE,
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
                    GetTokenInformation(token, TokenUser, buf, size, &size))
                {
                    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf);

                    wchar_t name[128], domain[128];
                    DWORD nlen = 128, dlen = 128;
                    SID_NAME_USE use;

                    if (LookupAccountSidW(nullptr, tu->User.Sid,
                                           name, &nlen,
                                           domain, &dlen, &use))
                    {
                        if (_wcsicmp(name, username) == 0) {
                            TerminateProcess(proc, 1);
                        }
                    }
                }
            }
            CloseHandle(token);
        }
        CloseHandle(proc);
    } while (Process32NextW(snap, &pe));

    CloseHandle(snap);
    return true;
}

// ========================================
// NTUSER.DAT Helpers
// ========================================
inline bool ntuserdat_backup()
{
    ensure_local_path();

    // Do not overwrite an existing baseline
    if (GetFileAttributesW(NTUSER_BACKUP_PATH) != INVALID_FILE_ATTRIBUTES)
        return true;

    return CopyFileW(
        STEAM_KIOSK_HIVE,
        NTUSER_BACKUP_PATH,
        TRUE   // fail if already exists
    ) != FALSE;
}

inline bool ntuserdat_restore()
{
    // Backup must exist
    if (GetFileAttributesW(NTUSER_BACKUP_PATH) == INVALID_FILE_ATTRIBUTES)
        return false;

    // Live hive must exist
    if (GetFileAttributesW(STEAM_KIOSK_HIVE) == INVALID_FILE_ATTRIBUTES)
        return false;

    // Best effort: remove attributes that might block overwrite
    SetFileAttributesW(STEAM_KIOSK_HIVE, FILE_ATTRIBUTE_NORMAL);

    return CopyFileW(
        NTUSER_BACKUP_PATH,
        STEAM_KIOSK_HIVE,
        FALSE   // overwrite
    ) != FALSE;
}

// ========================================
// Privileges
// ========================================
inline bool system_privilege_enable(HANDLE h_token, LPCWSTR privilege, BOOL enable)
{
    TOKEN_PRIVILEGES tp{};
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, privilege, &luid))
        return false;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    return AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
           GetLastError() == ERROR_SUCCESS;
}

// ========================================
// User Management
// =======================================

inline bool kiosk_user_exists()
{
    USER_INFO_0* buf = nullptr;
    DWORD entries_read, total_entries;
    auto res = NetUserEnum(nullptr, 0, FILTER_NORMAL_ACCOUNT,
                           reinterpret_cast<LPBYTE*>(&buf), MAX_PREFERRED_LENGTH,
                           &entries_read, &total_entries, nullptr);
    if (res != NERR_Success)
        return false;

    for (DWORD i = 0; i < entries_read; i++) {
        if (_wcsicmp(buf[i].usri0_name, STEAM_KIOSK_USER) == 0) {
            NetApiBufferFree(buf);
            return true;
        }
    }

    if (buf)
        NetApiBufferFree(buf);

    return false;
}

inline bool kiosk_user_create()
{
    USER_INFO_1 ui{};
    DWORD dw_error = 0;

    ui.usri1_name     = const_cast<LPWSTR>(STEAM_KIOSK_USER);
    ui.usri1_password = const_cast<LPWSTR>(STEAM_KIOSK_PASS);
    ui.usri1_priv     = USER_PRIV_USER;
    ui.usri1_flags    = UF_SCRIPT | UF_DONT_EXPIRE_PASSWD;

    return NetUserAdd(nullptr, 1, reinterpret_cast<LPBYTE>(&ui), &dw_error) == NERR_Success;
}

inline void kiosk_user_destroy()
{
    NetUserDel(nullptr, STEAM_KIOSK_USER);
}

// ========================================
// Kiosk Profile
// ========================================
inline int kiosk_profile_exists() {
    // Return codes:
    // 0 = profile exists and hive is readable
    // 1 = profile missing (NTUSER.DAT not present)
    // 3 = profile present but hive could not be loaded (corrupt/unreadable)

    if (GetFileAttributesW(STEAM_KIOSK_HIVE) == INVALID_FILE_ATTRIBUTES)
        return 1;

    // Try loading the hive via a temporary copy while holding the required
    // privileges. This avoids loading the live NTUSER.DAT directly which
    // can corrupt the user's profile if the system already has it loaded.
    scoped_privileges privs{ SE_RESTORE_NAME, SE_BACKUP_NAME };
    scoped_user_hive hive;

    if (!hive.ok())
        return 3;

    return 0;
}

// ========================================
// Autologin
// ========================================
inline void autologin_enable()
{
    HKEY h_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) != ERROR_SUCCESS)
        return;

    RegSetValueExW(h_key, L"AutoAdminLogon", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(L"1"), sizeof(L"1"));
    RegSetValueExW(h_key, L"DefaultUserName", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(STEAM_KIOSK_USER),
                   static_cast<DWORD>((wcslen(STEAM_KIOSK_USER) + 1) * sizeof(wchar_t)));
    RegSetValueExW(h_key, L"DefaultPassword", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(STEAM_KIOSK_PASS),
                   static_cast<DWORD>((wcslen(STEAM_KIOSK_PASS) + 1) * sizeof(wchar_t)));
    RegSetValueExW(h_key, L"DefaultDomainName", 0, REG_SZ,
                   reinterpret_cast<const BYTE*>(L"."), sizeof(L"."));

    RegCloseKey(h_key);
}

inline void autologin_disable()
{
    HKEY h_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS)
    {
        RegSetValueExW(h_key, L"AutoAdminLogon", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(L"0"), sizeof(L"0"));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
    }
}

inline bool autologin_status()
{
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
        type != REG_SZ || wcscmp(buf, L"1") != 0)
    {
        RegCloseKey(h_key);
        return false;
    }

    size = sizeof(buf);
    if (RegQueryValueExW(h_key, L"DefaultUserName", nullptr, &type,
                         (BYTE*)buf, &size) != ERROR_SUCCESS ||
        type != REG_SZ || wcscmp(buf, STEAM_KIOSK_USER) != 0)
    {
        RegCloseKey(h_key);
        return false;
    }

    RegCloseKey(h_key);
    return true;
}

// ========================================
// Other Users Prompt
// ========================================
bool _users_prompt(bool enable)
{
    HKEY h_key;
    DWORD value = enable ? 1 : 0;

    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            KEY_SET_VALUE,
            &h_key) != ERROR_SUCCESS)
        return false;

    LONG rc = RegSetValueExW(
        h_key,
        L"dontdisplaylastusername",
        0,
        REG_DWORD,
        reinterpret_cast<const BYTE*>(&value),
        sizeof(value));

    RegFlushKey(h_key);
    RegCloseKey(h_key);

    return rc == ERROR_SUCCESS;
}

inline bool users_prompt_status()
{
    HKEY h_key;
    DWORD value = 0;
    DWORD size  = sizeof(value);
    DWORD type  = 0;

    if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            0,
            KEY_QUERY_VALUE,
            &h_key) != ERROR_SUCCESS)
        return false;

    LONG rc = RegQueryValueExW(
        h_key,
        L"dontdisplaylastusername",
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(&value),
        &size);

    RegCloseKey(h_key);

    return rc == ERROR_SUCCESS &&
           type == REG_DWORD &&
           value == 1;
}

inline void users_prompt_enable()
{
    _users_prompt(true);
}

inline void users_prompt_disable()
{
    _users_prompt(false);
}

// ========================================
// Kiosk Shell
// ========================================
inline bool kiosk_set_shell(LPCWSTR shell_cmd)
{
    scoped_privileges privs{ SE_BACKUP_NAME, SE_RESTORE_NAME };
    scoped_user_hive hive;

    if (!hive.ok())
        return false;

    HKEY key;
    LONG rc = RegOpenKeyExW(
        HKEY_USERS,
        L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        0, KEY_SET_VALUE, &key);

    if (rc != ERROR_SUCCESS)
        return false;

    RegSetValueExW(key, L"Shell", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(shell_cmd),
        static_cast<DWORD>((wcslen(shell_cmd) + 1) * sizeof(wchar_t)));

    RegFlushKey(key);
    RegCloseKey(key);
    return true;
}
inline void kiosk_shell_bigpicture()
{
    kiosk_set_shell(BIG_PICTURE_EXEC);
}

inline void kiosk_shell_explorer()
{
    kiosk_set_shell(L"explorer.exe");
}

inline bool kiosk_shell_status()
{
    scoped_privileges privs{ SE_BACKUP_NAME };
    scoped_user_hive hive;

    if (!hive.ok())
        return false;

    wchar_t shell[512]{};
    DWORD size = sizeof(shell);

    LONG rc = RegGetValueW(
        HKEY_USERS,
        L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"Shell",
        RRF_RT_REG_SZ, nullptr, shell, &size);

    return rc == ERROR_SUCCESS && wcscmp(shell, BIG_PICTURE_EXEC) == 0;
}

// ========================================
// Session helpers
// ========================================
inline void logoff_user()  {
    ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0);
}

inline void     restart_user() { ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0); }

// ========================================
// UI Helpers
// ========================================
inline void update_ui()
{
    SendMessageW(h_autologin, BM_SETCHECK,
                 autologin_status() ? BST_CHECKED : BST_UNCHECKED, 0);
    SendMessageW(h_shell, BM_SETCHECK,
                 kiosk_shell_status() ? BST_CHECKED : BST_UNCHECKED, 0);
}

inline void prompt_first_login()
{
    wchar_t msg[512];
    swprintf_s(msg, L"Kiosk user created:\n\n"
                    L"Username: `%s`\n"
                    L"Password: `%s`\n\n"
                    L"After closing this message box, the login screen will appear.\n"
                    L"Login using the details provided above and wait for initialisation to completex`.\n"
                    L"Then logout, and log back into your personal user account to return to this helper.",
            STEAM_KIOSK_USER, STEAM_KIOSK_PASS);

    MessageBoxW(nullptr, msg, L"Steam Kiosk Setup", MB_OK | MB_ICONINFORMATION);
}

inline bool prompt_corrupt_profile()
{
    wchar_t msg[256];
    swprintf_s(msg, L"NTUSER.DAT for `%s` is corrupted and unreadable!\n\n"
                    L"Certain functionality may not work correctly.\n"
                    L"Please destroy the user profile and attempt running again.\n\n"
                    L"Attempt to restore from backup?",
              STEAM_KIOSK_USER);

    int result = MessageBoxW(nullptr, msg, L"Steam Kiosk Setup",
                             MB_YESNO | MB_ICONERROR);

    return result == IDYES; // true if user clicked Yes, false if No
}

inline void switch_to_other_user_screen()
{
    autologin_disable();
    WTSDisconnectSession(WTS_CURRENT_SERVER_HANDLE,
                         WTS_CURRENT_SESSION, FALSE);
}

// ======================================== 
// Delete User Profile
// ========================================
inline bool delete_kiosk_user_profile()
{
    DWORD attrs = GetFileAttributesW(STEAM_KIOSK_PROFILE_DIR);

    // Nothing to do
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return true;

    // Must be a directory
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY))
        return false;

    return delete_directory_recursive(STEAM_KIOSK_PROFILE_DIR);
}

inline bool destroy_kiosk_user_completely()
{
    // 1. Disable autologin first
    autologin_disable();

    // 2. Kill any remaining kiosk processes
    terminate_processes_for_user(STEAM_KIOSK_USER);

    // Give Windows a moment to release handles
    Sleep(500);

    // 3. Delete profile directory (NTUSER.DAT must not be loaded)
    if (!delete_kiosk_user_profile())
        return false;

    // 4. Delete the user account
    kiosk_user_destroy();

    return true;
}

// ========================================
// Main Window Procedure
// ========================================
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
    case WM_COMMAND:
        if ((HWND)lParam == h_autologin)
            autologin_status() ? autologin_disable() : autologin_enable();
        else if ((HWND)lParam == h_shell)
            kiosk_shell_status() ? kiosk_shell_explorer() : kiosk_shell_bigpicture();
        else if ((HWND)lParam == h_users_prompt)
            users_prompt_status() ? users_prompt_disable() : users_prompt_enable();
        else if ((HWND)lParam == h_logoff)
            logoff_user();
        else if ((HWND)lParam == h_restart)
            restart_user();
        else if ((HWND)lParam == h_delete_user)
        {
            if (MessageBoxW(hwnd, L"Are you sure you want to delete the Steam Kiosk user?",
                            L"Confirm Delete", MB_YESNO | MB_ICONWARNING) == IDYES)
            {
                if (destroy_kiosk_user_completely()) {
                    MessageBoxW(hwnd, L"Steam Kiosk user and profile deleted successfully.",
                                L"Deleted", MB_OK | MB_ICONINFORMATION);
                    ExitProcess(0);
                } else {
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
void kiosk_setup_if_needed()
{
    if (!kiosk_user_exists()) {
        if (!kiosk_user_create()) {
            MessageBoxW(nullptr, L"Failed to create Steam Kiosk user.", L"Error", MB_OK | MB_ICONERROR);
            ExitProcess(1);
        }
    }
    
    int profile_status = kiosk_profile_exists();
    if (profile_status == 1) {
        // First login needed
        prompt_first_login();
        users_prompt_enable();
        switch_to_other_user_screen();
        Sleep(5000); // Give some time for the user to switch
        users_prompt_disable();
        Sleep(20000);
        MessageBoxW(nullptr, L"Please press OK to continue.\n",
                             L"And to proceed to backuping up the profile",
                             MB_OK | MB_ICONINFORMATION);
        Sleep(1000);
        if (ntuserdat_backup()) {
            MessageBoxW(nullptr, L"Profile backup created successfully.",
                                 L"Backup Created", MB_OK | MB_ICONINFORMATION);
        } else {
            MessageBoxW(nullptr, L"Failed to create profile backup.",
                                 L"Backup Failed", MB_OK | MB_ICONERROR);
        }
    } else if (profile_status == 3) {
        if (prompt_corrupt_profile()) {
            // kiosk_user_destroy();
            if (ntuserdat_restore()) {
                MessageBoxW(nullptr, L"Profile restored from backup. Please restart the application.",
                                     L"Profile Restored", MB_OK | MB_ICONINFORMATION);
            } else {
                MessageBoxW(nullptr, L"Failed to restore profile from backup. Please restart and try again.\nIf it continues, please delete NTUSER.DAT and try again. If all else fails, please delete the user and its folder and try again.",
                                     L"Profile Restore Failed", MB_OK | MB_ICONERROR);
            }
            ExitProcess(1);
        }
    }
}

// ========================================
// Main Entry
// ========================================
int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int)
{
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
    h_title = CreateWindowW(L"STATIC", L"Steam Kiosk Helper",
                            WS_CHILD | WS_VISIBLE | SS_CENTER,
                            0, 10, MAIN_WINDOW_WIDTH, 30,
                            hwnd, nullptr, hInst, nullptr);

    HFONT h_font = CreateFontW(FONT_SIZE, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                               CLEARTYPE_QUALITY, VARIABLE_PITCH, L"Segoe UI");

    SendMessageW(h_title, WM_SETFONT, (WPARAM)h_font, TRUE);

    // Buttons / Checkboxes 2x2 grid
    // 20+112+12+112+12+112+20 
    // ((400−(20×2))−(12×2))×1/3
    h_autologin = CreateWindowW(L"BUTTON", L"Autologin",
                                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                20, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                                hwnd, nullptr, hInst, nullptr);

    h_shell = CreateWindowW(L"BUTTON", L"Big-Picture Shell",
                             WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                             144, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                             hwnd, nullptr, hInst, nullptr);

    h_users_prompt = CreateWindowW(L"BUTTON", L"User Prompt",
                             WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                             268, 60, TOGGLE_WIDTH, BUTTON_HEIGHT,
                             hwnd, nullptr, hInst, nullptr);

    h_logoff = CreateWindowW(L"BUTTON", L"Log Off",
                              WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              50, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                              hwnd, nullptr, hInst, nullptr);

    h_restart = CreateWindowW(L"BUTTON", L"Restart",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               220, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                               hwnd, nullptr, hInst, nullptr);
                               // Delete User button (bottom middle)
    h_delete_user = CreateWindowW(L"BUTTON", L"Delete User",
                              WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              (MAIN_WINDOW_WIDTH - BUTTON_WIDTH) / 2, // center horizontally
                              180, // below the 2x2 grid (adjust spacing)
                              BUTTON_WIDTH, BUTTON_HEIGHT,
                              hwnd, nullptr, hInst, nullptr);

    SendMessageW(h_autologin, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_shell, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_users_prompt, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_logoff, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_restart, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_delete_user, WM_SETFONT, (WPARAM)h_font, TRUE);

    ShowWindow(hwnd, SW_SHOW);
    update_ui();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
