// steam_kiosk.cpp
#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <wchar.h>
#include <lm.h>
#include <wtsapi32.h>
#include <shellapi.h>
#include <thread>

// ========================================
// Constants
// ========================================
inline constexpr auto STATE_PATH        = L"C:\\tools\\steam_shell\\state.json";
inline constexpr auto STEAM_EXE_PATH    = L"C:\\Program Files (x86)\\Steam\\steam.exe";
inline constexpr auto BIG_PICTURE_EXEC  = L"C:\\Program Files (x86)\\Steam\\steam.exe -bigpicture";
inline constexpr auto STEAM_KIOSK_USER  = L"steam_kiosk";
inline constexpr auto STEAM_KIOSK_PASS  = L"valve";
inline constexpr auto STEAM_KIOSK_HIVE  = L"C:\\Users\\steam_kiosk\\NTUSER.DAT";

inline constexpr int MAIN_WINDOW_WIDTH  = 400;
inline constexpr int MAIN_WINDOW_HEIGHT = 300;
inline constexpr int TOGGLE_WIDTH       = 112; // ((400−(20×2))−(12×2))×1/3
inline constexpr int BUTTON_WIDTH       = 150;
inline constexpr int BUTTON_HEIGHT      = 40;
inline constexpr int FONT_SIZE          = 16;

// ========================================
// Global Window Handles
// ========================================
HWND h_title;
HWND h_autologin;
HWND h_shell;
HWND h_users_prompt;
HWND h_logoff;
HWND h_restart;
HWND h_delete_user;

// ========================================
// Forward declarations
// ========================================
void update_ui();
void prompt_first_login();
void switch_to_other_user_screen();
void kiosk_setup_if_needed();

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
        swprintf_s(temp_hive, L"C:\\tools\\steam_shell\\NTUSER_TEMP.DAT");

        if (!CopyFileW(STEAM_KIOSK_HIVE, temp_hive, FALSE))
            return;

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
// ========================================
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
    const wchar_t* hive_name = L"STEAM_KIOSK";
    wchar_t user_hive[MAX_PATH]{};
    wcscpy_s(user_hive, STEAM_KIOSK_HIVE);

    if (GetFileAttributesW(user_hive) == INVALID_FILE_ATTRIBUTES)  
        return 1;
    if (RegLoadKeyW(HKEY_USERS, hive_name, user_hive) != ERROR_SUCCESS)
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

    DeleteFileW(STATE_PATH);
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
                    L"Do you wish to continue?",
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
                kiosk_user_destroy();
                MessageBoxW(hwnd, L"Steam Kiosk user deleted.\nPlease delete its folder", L"Deleted", MB_OK | MB_ICONINFORMATION);
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
        Sleep(10000); // Give some time for the user to switch
        users_prompt_disable();
    } else if (profile_status == 3) {
        if (!prompt_corrupt_profile()) {
            // kiosk_user_destroy();
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
