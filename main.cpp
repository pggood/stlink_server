#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include "stlink_server.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <dbt.h>
#include <filesystem>
#include <vector>
#include <regex>
#include <sstream>
#include <algorithm>

// Undefine min/max macros to avoid conflict with std::min
#undef min
#undef max

using std::cout;
using std::cerr;
using std::endl;
using std::string;

void log_message(const string& message) {
    cout << "[INFO] " << message << endl;
}

void log_error(const string& message, DWORD error_code = 0) {
    cerr << "[ERROR] " << message;
    if (error_code) {
        LPVOID msg_buf;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg_buf, 0, NULL);
        cerr << " (Error code: " << error_code << ": " << (char*)msg_buf << ")";
        LocalFree(msg_buf);
    }
    cerr << endl;
}

bool compare_versions(const string& v1, const string& v2) {
    std::vector<int> v1_parts, v2_parts;
    std::stringstream ss1(v1), ss2(v2);
    string part;

    // Parse version string v1
    while (std::getline(ss1, part, '.')) {
        try {
            if (part.empty() || part.find_first_not_of("0123456789") != string::npos) {
                log_error("Invalid version component in v1: " + part);
                continue;
            }
            v1_parts.push_back(std::stoi(part));
        }
        catch (const std::exception& e) {
            log_error("Failed to parse version component in v1: " + part + ", error: " + e.what());
            continue;
        }
    }

    // Parse version string v2
    while (std::getline(ss2, part, '.')) {
        try {
            if (part.empty() || part.find_first_not_of("0123456789") != string::npos) {
                log_error("Invalid version component in v2: " + part);
                continue;
            }
            v2_parts.push_back(std::stoi(part));
        }
        catch (const std::exception& e) {
            log_error("Failed to parse version component in v2: " + part + ", error: " + e.what());
            continue;
        }
    }

    // If both version parts are empty, consider them equal
    if (v1_parts.empty() && v2_parts.empty()) {
        return false;
    }

    size_t min_size = std::min(v1_parts.size(), v2_parts.size());
    for (size_t i = 0; i < min_size; i++) {
        if (v1_parts[i] != v2_parts[i]) {
            return v1_parts[i] > v2_parts[i];
        }
    }
    return v1_parts.size() > v2_parts.size();
}

string find_latest_gdb_server() {
    string latest_path;
    string latest_version;

    for (char drive = 'C'; drive <= 'Z'; drive++) {
        string drive_path = string(1, drive) + ":\\ST";
        if (!std::filesystem::exists(drive_path)) continue;

        for (const auto& entry : std::filesystem::directory_iterator(drive_path)) {
            if (!entry.is_directory()) continue;
            string dir_name = entry.path().filename().string();

            std::regex version_regex(R"(STM32CubeIDE_([\d.]+))");
            std::smatch match;
            if (std::regex_match(dir_name, match, version_regex)) {
                string version = match[1].str();

                if (latest_version.empty() || compare_versions(version, latest_version)) {
                    string plugins_path = entry.path().string() + "\\STM32CubeIDE\\plugins";
                    for (const auto& plugin : std::filesystem::recursive_directory_iterator(plugins_path)) {
                        if (plugin.path().filename() == "ST-LINK_gdbserver.exe") {
                            latest_path = plugin.path().string();
                            latest_version = version;
                            break;
                        }
                    }
                }
            }
        }
    }

    if (!latest_path.empty()) {
        log_message("Found latest ST-LINK_gdbserver.exe: " + latest_path);
    }
    else {
        log_error("No ST-LINK_gdbserver.exe found on any drive");
    }
    return latest_path;
}

string get_cubeprogrammer_path(const string& gdb_server_path) {
    std::filesystem::path gdb_path(gdb_server_path);
    auto parent = gdb_path.parent_path().parent_path().parent_path().parent_path();
    string plugins_path = parent.string();

    for (const auto& entry : std::filesystem::directory_iterator(plugins_path)) {
        if (entry.path().filename().string().find("cubeprogrammer") != string::npos) {
            string cp_path = entry.path().string() + "\\tools\\bin";
            log_message("Found CubeProgrammer path: " + cp_path);
            return cp_path;
        }
    }
    log_error("Could not find CubeProgrammer path");
    return "";
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static STLinkServer* server = nullptr;
    static string gdb_server_path;
    static string cubeprogrammer_path;

    if (msg == WM_CREATE) {
        server = reinterpret_cast<STLinkServer*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
        gdb_server_path = find_latest_gdb_server();
        if (!gdb_server_path.empty()) {
            cubeprogrammer_path = get_cubeprogrammer_path(gdb_server_path);
        }
    }
    if (msg == WM_DEVICECHANGE) {
        if (wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE) {
            bool arrived = (wParam == DBT_DEVICEARRIVAL);
            if (server) {
                int res = server->handle_hotplug(arrived);
                log_message(arrived ? "Device arrival detected" : "Device removal detected");
                if (res != 0) {
                    log_error("Hotplug handling failed", res);
                }
                if (arrived && !gdb_server_path.empty() && !cubeprogrammer_path.empty()) {
                    string cmd = "\"" + gdb_server_path + "\" -p 61234 -l 1 -d -s -cp \"" + cubeprogrammer_path + "\" -m 0 -k";
                    log_message("Executing: " + cmd);

                    std::wstring wcmd(cmd.begin(), cmd.end());
                    STARTUPINFOW si = { sizeof(si) };
                    PROCESS_INFORMATION pi;
                    if (CreateProcessW(NULL, wcmd.data(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                        CloseHandle(pi.hProcess);
                        CloseHandle(pi.hThread);
                        log_message("ST-LINK_gdbserver started successfully");
                    }
                    else {
                        log_error("Failed to execute ST-LINK_gdbserver", GetLastError());
                    }
                }
            }
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

HWND setup_device_notifications(STLinkServer& server) {
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = L"STLinkDeviceWindow";
    RegisterClass(&wc);

    HWND hwnd = CreateWindow(L"STLinkDeviceWindow", L"STLink Device Window", 0, 0, 0, 0, 0,
        HWND_MESSAGE, NULL, GetModuleHandle(NULL), &server);
    if (!hwnd) {
        log_error("Failed to create message window", GetLastError());
        return nullptr;
    }

    DEV_BROADCAST_DEVICEINTERFACE filter = { sizeof(DEV_BROADCAST_DEVICEINTERFACE) };
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };

    HDEVNOTIFY notify = RegisterDeviceNotification(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (!notify) {
        log_error("Failed to register device notification", GetLastError());
        DestroyWindow(hwnd);
        return nullptr;
    }
    return hwnd;
}

void print_help() {
    cout << "stlink-server\n"
        << "--help       | -h       display this help\n"
        << "--version    | -v       display STLinkserver version\n"
        << "--port       | -p       set tcp listening port\n"
        << "--debug      | -d       set debug level <0-5> (incremental, 0: Error, 1:Info, 2:Warning, 3:STlink, 4:Debug, 5:Usb)\n"
        << "--auto-exit  | -a       exit() when there is no more client\n"
        << "--log_output | -l       redirect log output to file <name>\n";
}

int main(int argc, char* argv[]) {
    int debug_level = 0;
    int port = 7184;
    bool auto_exit = false;
    string log_file_path;

    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        else if (arg == "--version" || arg == "-v") {
            cout << "stlink-server version 1.0.0\n";
            return 0;
        }
        else if ((arg == "--port" || arg == "-p") && i + 1 < argc) {
            try {
                port = std::stoi(argv[++i]);
                if (port < 1 || port > 65535) {
                    log_error("Invalid port number. Must be between 1 and 65535.");
                    return 1;
                }
            }
            catch (...) {
                log_error("Invalid port number");
                return 1;
            }
        }
        else if ((arg == "--debug" || arg == "-d") && i + 1 < argc) {
            try {
                debug_level = std::stoi(argv[++i]);
                if (debug_level < 0 || debug_level > 5) {
                    log_error("Invalid debug level. Must be between 0 and 5.");
                    return 1;
                }
            }
            catch (...) {
                log_error("Invalid debug level");
                return 1;
            }
        }
        else if (arg == "--auto-exit" || arg == "-a") {
            auto_exit = true;
        }
        else if ((arg == "--log_output" || arg == "-l") && i + 1 < argc) {
            log_file_path = argv[++i];
        }
        else {
            log_error("Unknown or invalid argument: " + arg);
            print_help();
            return 1;
        }
    }

    try {
        log_message("Starting STLink Server...");
        STLinkServer server(port, auto_exit, log_file_path);

        HWND hwnd = setup_device_notifications(server);
        if (!hwnd) {
            log_error("Device notification setup failed");
            return 1;
        }

        int res = server.start(debug_level);
        if (res != 0) {
            log_error("Failed to start server", res);
            DestroyWindow(hwnd);
            return 1;
        }
        log_message("STLink Server started successfully");

        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        log_message("Exiting...");
        DestroyWindow(hwnd);
        return 0;
    }
    catch (const std::exception& e) {
        log_error("Exception: " + string(e.what()));
        return 1;
    }
}