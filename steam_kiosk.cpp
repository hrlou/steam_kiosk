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

inline constexpr int MAIN_WINDOW_WIDTH  = 400;
inline constexpr int MAIN_WINDOW_HEIGHT = 200;
inline constexpr int BUTTON_WIDTH       = 150;
inline constexpr int BUTTON_HEIGHT      = 40;
inline constexpr int FONT_SIZE          = 16;

// ========================================
// Global Window Handles
// ========================================
HWND h_title;
HWND h_autologin;
HWND h_shell;
HWND h_logoff;
HWND h_restart;

// ========================================
// Forward declarations
// ========================================
void update_ui();
void prompt_first_login();
void switch_to_other_user_screen();
void kiosk_setup_if_needed();

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
inline bool kiosk_profile_exists()
{
    wchar_t path[MAX_PATH];
    swprintf_s(path, L"C:\\Users\\%s\\NTUSER.DAT", STEAM_KIOSK_USER);
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
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
inline void users_prompt_enable()
{
    HKEY h_key;
    DWORD one = 1;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS)
    {
        RegSetValueExW(h_key, L"dontdisplaylastusername", 0, REG_DWORD,
                       (const BYTE*)&one, sizeof(one));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
    }
}

inline void users_prompt_disable()
{
    HKEY h_key;
    DWORD zero = 0;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS)
    {
        RegSetValueExW(h_key, L"dontdisplaylastusername", 0, REG_DWORD,
                       (const BYTE*)&zero, sizeof(zero));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
    }
}

// ========================================
// Kiosk Shell
// ========================================
inline void kiosk_shell_bigpicture()
{
    HANDLE h_token;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                         &h_token))
    {
        system_privilege_enable(h_token, SE_RESTORE_NAME, TRUE);
        system_privilege_enable(h_token, SE_BACKUP_NAME, TRUE);
        CloseHandle(h_token);
    }

    const wchar_t* hive_name = L"STEAM_KIOSK";
    wchar_t user_hive[MAX_PATH]{};
    swprintf_s(user_hive, L"C:\\Users\\%s\\NTUSER.DAT", STEAM_KIOSK_USER);

    if (RegLoadKeyW(HKEY_USERS, hive_name, user_hive) != ERROR_SUCCESS)
        return;

    HKEY h_key;
    if (RegOpenKeyExW(HKEY_USERS,
                      L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS)
    {
        RegSetValueExW(h_key, L"Shell", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(BIG_PICTURE_EXEC),
                       static_cast<DWORD>((wcslen(BIG_PICTURE_EXEC) + 1) * sizeof(wchar_t)));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
    }

    RegUnLoadKeyW(HKEY_USERS, hive_name);
}

inline void kiosk_shell_explorer()
{
    const wchar_t* hive_name = L"STEAM_KIOSK";
    wchar_t user_hive[MAX_PATH]{};
    swprintf_s(user_hive, L"C:\\Users\\%s\\NTUSER.DAT", STEAM_KIOSK_USER);

    if (RegLoadKeyW(HKEY_USERS, hive_name, user_hive) != ERROR_SUCCESS)
        return;

    HKEY h_key;
    if (RegOpenKeyExW(HKEY_USERS,
                      L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                      0, KEY_SET_VALUE, &h_key) == ERROR_SUCCESS)
    {
        const wchar_t* shell = L"explorer.exe";
        RegSetValueExW(h_key, L"Shell", 0, REG_SZ,
                       reinterpret_cast<const BYTE*>(shell),
                       static_cast<DWORD>((wcslen(shell) + 1) * sizeof(wchar_t)));
        RegFlushKey(h_key);
        RegCloseKey(h_key);
    }

    RegUnLoadKeyW(HKEY_USERS, hive_name);
}

inline bool kiosk_shell_status()
{
    const wchar_t* hive_name = L"STEAM_KIOSK";
    wchar_t user_hive[MAX_PATH]{};
    swprintf_s(user_hive, L"C:\\Users\\%s\\NTUSER.DAT", STEAM_KIOSK_USER);

    if (RegLoadKeyW(HKEY_USERS, hive_name, user_hive) != ERROR_SUCCESS)
        return false;

    wchar_t shell[512]{};
    DWORD size = sizeof(shell);

    LONG ret = RegGetValueW(HKEY_USERS,
                            L"STEAM_KIOSK\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
                            L"Shell", RRF_RT_REG_SZ, nullptr,
                            shell, &size);

    bool result = (ret == ERROR_SUCCESS) &&
                  (wcscmp(shell, BIG_PICTURE_EXEC) == 0);

    RegUnLoadKeyW(HKEY_USERS, hive_name);
    return result;
}

// ========================================
// Session helpers
// ========================================
inline void logoff_user()  { ExitWindowsEx(EWX_LOGOFF | EWX_FORCE, 0); }
inline void restart_user() { ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0); }

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
    MessageBoxW(nullptr,
        L"Steam Kiosk user created.\n\n"
        L"Please log in once using username: steam_kiosk\n"
        L"Password: valve\n\n"
        L"After login, the UI will function properly.",
        L"Steam Kiosk Setup", MB_OK | MB_ICONINFORMATION);
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
        else if ((HWND)lParam == h_logoff)
            logoff_user();
        else if ((HWND)lParam == h_restart)
            restart_user();

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

    if (!kiosk_profile_exists()) {
        autologin_enable();
        prompt_first_login();
        users_prompt_enable();
        switch_to_other_user_screen();
        ExitProcess(0);
    }

    autologin_disable();
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
    h_autologin = CreateWindowW(L"BUTTON", L"Autologin",
                                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                50, 60, BUTTON_WIDTH, BUTTON_HEIGHT,
                                hwnd, nullptr, hInst, nullptr);

    h_shell = CreateWindowW(L"BUTTON", L"Big-Picture Shell",
                             WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                             220, 60, BUTTON_WIDTH, BUTTON_HEIGHT,
                             hwnd, nullptr, hInst, nullptr);

    h_logoff = CreateWindowW(L"BUTTON", L"Log Off",
                              WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                              50, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                              hwnd, nullptr, hInst, nullptr);

    h_restart = CreateWindowW(L"BUTTON", L"Restart",
                               WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                               220, 120, BUTTON_WIDTH, BUTTON_HEIGHT,
                               hwnd, nullptr, hInst, nullptr);

    SendMessageW(h_autologin, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_shell, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_logoff, WM_SETFONT, (WPARAM)h_font, TRUE);
    SendMessageW(h_restart, WM_SETFONT, (WPARAM)h_font, TRUE);

    ShowWindow(hwnd, SW_SHOW);
    update_ui();

    MSG msg{};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    return 0;
}
