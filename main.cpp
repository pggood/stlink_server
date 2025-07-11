#define WIN32_LEAN_AND_MEAN
#include "stlink_server.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <dbt.h>

void log_message(const std::string& message) {
    std::cout << "[INFO] " << message << std::endl;
}

void log_error(const std::string& message, DWORD error_code = 0) {
    std::cerr << "[ERROR] " << message;
    if (error_code) {
        LPVOID msg_buf;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, error_code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&msg_buf, 0, NULL);
        std::cerr << " (Error code: " << error_code << ": " << (char*)msg_buf << ")";
        LocalFree(msg_buf);
    }
    std::cerr << std::endl;
}

// Windows device notification handler
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    static STLinkServer* server = nullptr;
    if (msg == WM_CREATE) {
        server = reinterpret_cast<STLinkServer*>(reinterpret_cast<CREATESTRUCT*>(lParam)->lpCreateParams);
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
    filter.dbcc_classguid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} }; // WinUSB GUID

    HDEVNOTIFY notify = RegisterDeviceNotification(hwnd, &filter, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (!notify) {
        log_error("Failed to register device notification", GetLastError());
        DestroyWindow(hwnd);
        return nullptr;
    }
    return hwnd;
}

void print_menu() {
    std::cout << "\nSTLink Server Commands:\n"
        << "1. Blink LED\n"
        << "2. Erase Flash\n"
        << "3. Get Firmware Version\n"
        << "4. Enter SWD Mode\n"
        << "5. Exit\n"
        << "Enter choice (1-5): ";
}

int main() {
    try {
        log_message("Starting STLink Server...");
        STLinkServer server;

        // Set up device notifications
        HWND hwnd = setup_device_notifications(server);
        if (!hwnd) {
            log_error("Device notification setup failed");
            return 1;
        }

        // Start the server
        int res = server.start();
        if (res != 0) {
            log_error("Failed to start server", res);
            DestroyWindow(hwnd);
            return 1;
        }
        log_message("STLink Server started successfully");

        // Command-line interface with message pump
        STLinkServer::DebugInterface iface = { .swd_freq = 24000000, .target_voltage = 3 };
        MSG msg;
        while (true) {
            // Process Windows messages for device notifications
            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }

            print_menu();
            std::string input;
            std::getline(std::cin, input);
            int choice;
            try {
                choice = std::stoi(input);
            }
            catch (...) {
                log_error("Invalid input");
                continue;
            }

            switch (choice) {
            case 1: {
                res = server.blink_led();
                if (res == 0) {
                    log_message("LED blinked successfully");
                }
                else {
                    log_error("Failed to blink LED", res);
                }
                break;
            }
            case 2: {
                res = server.erase_flash();
                if (res == 0) {
                    log_message("Flash erased successfully");
                }
                else {
                    log_error("Failed to erase flash", res);
                }
                break;
            }
            case 3: {
                res = server.get_firmware_version(iface);
                if (res == 0) {
                    std::cout << "Firmware Version: Major=" << (int)iface.fw_major_ver
                        << ", JTAG=" << (int)iface.fw_jtag_ver << std::endl;
                }
                else {
                    log_error("Failed to get firmware version", res);
                }
                break;
            }
            case 4: {
                res = server.enter_swd_mode();
                if (res == 0) {
                    log_message("Entered SWD mode successfully");
                }
                else {
                    log_error("Failed to enter SWD mode", res);
                }
                break;
            }
            case 5: {
                log_message("Exiting...");
                UnregisterDeviceNotification(hwnd);
                DestroyWindow(hwnd);
                return 0;
            }
            default:
                log_error("Invalid choice");
            }
        }
    }
    catch (const std::exception& e) {
        log_error("Exception: " + std::string(e.what()));
        return 1;
    }
}