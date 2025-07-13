#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include "stlink_server.h"
#include <stdexcept>
#include <vector>
#include <cstdio>
#include <cstring>
#include <ws2tcpip.h>

STLinkServer::STLinkServer(int port, bool auto_exit, const std::string& log_file_path)
    : device_handle(NULL),
    winusb_handle(NULL),
    server_socket(INVALID_SOCKET),
    server_thread(NULL),
    device_key(0),
    serial(64, '\0'),
    rx_ep(0),
    tx_ep(0),
    trace_ep(0),
    debug_level(0),
    debug_counter(0),
    port(port),
    auto_exit(auto_exit) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
    if (!log_file_path.empty()) {
        log_file.open(log_file_path, std::ios::out | std::ios::app);
        if (!log_file.is_open()) {
            throw std::runtime_error("Failed to open log file: " + log_file_path);
        }
    }
}

STLinkServer::~STLinkServer() {
    if (winusb_handle) {
        WinUsb_Free(winusb_handle);
    }
    if (device_handle) {
        CloseHandle(device_handle);
    }
    if (server_socket != INVALID_SOCKET) {
        closesocket(server_socket);
    }
    if (log_file.is_open()) {
        log_file.close();
    }
    WSACleanup();
}

void STLinkServer::debug_log(int level, const char* format, ...) {
    if (level <= debug_level) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        int len = snprintf(buffer, sizeof(buffer), "Debug: %d %d : ", ++debug_counter, GetTickCount());
        vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
        strcat(buffer, "\n");
        if (log_file.is_open()) {
            log_file << buffer;
            log_file.flush();
        }
        else {
            printf("%s", buffer);
        }
        va_end(args);
    }
}

void STLinkServer::info_log(const char* format, ...) {
    va_list args;
    va_start(args, format);
    char buffer[1024];
    int len = snprintf(buffer, sizeof(buffer), "Info : %d %d : ", ++debug_counter, GetTickCount());
    vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
    strcat(buffer, "\n");
    if (log_file.is_open()) {
        log_file << buffer;
        log_file.flush();
    }
    else {
        printf("%s", buffer);
    }
    va_end(args);
}

void STLinkServer::stlk_log(const char* format, ...) {
    if (debug_level > 0) {
        va_list args;
        va_start(args, format);
        char buffer[1024];
        int len = snprintf(buffer, sizeof(buffer), "Stlk : %d %d : ", debug_counter++, GetTickCount());
        vsnprintf(buffer + len, sizeof(buffer) - len, format, args);
        strcat(buffer, "\n");
        if (log_file.is_open()) {
            log_file << buffer;
            log_file.flush();
        }
        else {
            printf("%s", buffer);
        }
        va_end(args);
    }
}

int STLinkServer::create_listening_sockets() {
    debug_log(1, "create_listening_sockets");
    debug_log(2, "Entering create_listening_sockets()");
    debug_log(3, "Creating the list of sockets to listen for ...");

    struct addrinfo hints = { 0 };
    struct addrinfo* result = NULL;
    int iResult;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);
    debug_log(4, "interface, tcp port: (null), %s", port_str);
    info_log("default port : %s", port_str);

    iResult = getaddrinfo(NULL, port_str, &hints, &result);
    if (iResult != 0) {
        return -1;
    }

    debug_log(6, "getaddrinfo successful. Enumerating the returned addresses ...");

    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        debug_log(7, "Processing Address %p returned by getaddrinfo(%d) : (null)",
            ptr, (ptr == result ? 1 : 2));

        server_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (server_socket == INVALID_SOCKET) {
            continue;
        }

        debug_log(8, "Created socket with handle = %d", server_socket);

        iResult = bind(server_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
            continue;
        }

        char ipstr[INET6_ADDRSTRLEN];
        void* addr;
        if (ptr->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)ptr->ai_addr;
            addr = &(ipv4->sin_addr);
        }
        else {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)ptr->ai_addr;
            addr = &(ipv6->sin6_addr);
        }
        inet_ntop(ptr->ai_family, addr, ipstr, sizeof(ipstr));
        info_log("%s:%s", ipstr, port_str);

        debug_log(10, "Socket bound successfully");

        u_long iMode = 1;
        iResult = ioctlsocket(server_socket, FIONBIO, &iMode);
        if (iResult != NO_ERROR) {
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
            continue;
        }

        debug_log(11, "Non Blocking Setting");
        debug_log(12, "alloc_init_sock_info : Allocated %p", (void*)server_socket);
        debug_log(13, "Added socket to list of listening sockets");
        break;
    }

    freeaddrinfo(result);
    debug_log(14, "Freed the memory allocated for res by getaddrinfo");

    if (server_socket == INVALID_SOCKET) {
        return -1;
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(server_socket);
        server_socket = INVALID_SOCKET;
        return -1;
    }

    debug_log(15, "Exiting create_listening_sockets()");
    return 0;
}

std::string STLinkServer::extract_serial_number(const WCHAR* device_path) {
    char narrow_path[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, device_path, -1, narrow_path, MAX_PATH, NULL, NULL);

    std::cmatch match;
    std::regex re(R"(\\\?\\usb#vid_[0-9a-fA-F]{4}&pid_[0-9a-fA-F]{4}#([^#]+)#)");
    if (std::regex_search(narrow_path, match, re) && match.size() > 1) {
        return match[1].str();
    }
    return "UNKNOWN";
}

int STLinkServer::usb_init() {
    GUID winusb_guid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
    HDEVINFO device_info = SetupDiGetClassDevs(&winusb_guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (device_info == INVALID_HANDLE_VALUE) {
        debug_log(1, "SetupDiGetClassDevs failed: 0x%08x", GetLastError());
        return -1;
    }

    SP_DEVICE_INTERFACE_DATA interface_data = { sizeof(SP_DEVICE_INTERFACE_DATA) };
    DWORD index = 0;
    bool stlink_found = false;

    while (SetupDiEnumDeviceInterfaces(device_info, NULL, &winusb_guid, index, &interface_data)) {
        DWORD required_size = 0;
        SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, NULL, 0, &required_size, NULL);

        PSP_DEVICE_INTERFACE_DETAIL_DATA detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        if (!detail) {
            debug_log(2, "Memory allocation failed");
            SetupDiDestroyDeviceInfoList(device_info);
            return -1;
        }

        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        SP_DEVINFO_DATA devinfo_data = { sizeof(SP_DEVINFO_DATA) };

        if (SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, detail, required_size, NULL, &devinfo_data)) {
            if (wcsstr(detail->DevicePath, L"vid_0483") && wcsstr(detail->DevicePath, L"pid_3748")) {
                device_handle = CreateFile(detail->DevicePath,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL,
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED,
                    NULL);

                if (device_handle != INVALID_HANDLE_VALUE) {
                    std::string serial_number = extract_serial_number(detail->DevicePath);
                    debug_log(3, "Opening STLink device: %s", serial_number.c_str());

                    if (WinUsb_Initialize(device_handle, &winusb_handle)) {
                        ULONG timeout = 3000;
                        WinUsb_SetPipePolicy(winusb_handle, 0xFF, PIPE_TRANSFER_TIMEOUT, sizeof(timeout), &timeout);

                        USB_INTERFACE_DESCRIPTOR iface_desc;
                        if (WinUsb_QueryInterfaceSettings(winusb_handle, 0, &iface_desc)) {
                            for (UCHAR i = 0; i < iface_desc.bNumEndpoints; i++) {
                                WINUSB_PIPE_INFORMATION pipe_info;
                                if (WinUsb_QueryPipe(winusb_handle, 0, i, &pipe_info)) {
                                    if (pipe_info.PipeType == UsbdPipeTypeBulk) {
                                        if (USB_ENDPOINT_DIRECTION_IN(pipe_info.PipeId)) {
                                            rx_ep = pipe_info.PipeId;
                                            debug_log(4, "Found BULK IN endpoint: 0x%02X", rx_ep);
                                        }
                                        else {
                                            tx_ep = pipe_info.PipeId;
                                            debug_log(4, "Found BULK OUT endpoint: 0x%02X", tx_ep);
                                        }
                                    }
                                }
                            }

                            if (rx_ep && tx_ep) {
                                uint8_t version_cmd[16] = { CMD_GET_VERSION };
                                uint8_t response[16] = { 0 };
                                ULONG bytes_transferred = 0;

                                if (WinUsb_WritePipe(winusb_handle, tx_ep, version_cmd, sizeof(version_cmd), &bytes_transferred, NULL) &&
                                    WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
                                    stlink_found = true;
                                    this->serial = serial_number;
                                    debug_log(5, "STLink initialized successfully");
                                    free(detail);
                                    break;
                                }
                                else {
                                    debug_log(6, "Communication test failed: 0x%08x", GetLastError());
                                }
                            }
                            else {
                                debug_log(7, "Missing required endpoints");
                            }
                        }
                        else {
                            debug_log(8, "QueryInterfaceSettings failed: 0x%08x", GetLastError());
                        }
                    }
                    else {
                        debug_log(9, "WinUsb_Initialize failed: 0x%08x", GetLastError());
                    }

                    if (!stlink_found) {
                        if (winusb_handle) WinUsb_Free(winusb_handle);
                        CloseHandle(device_handle);
                        winusb_handle = NULL;
                        device_handle = NULL;
                    }
                }
                else {
                    debug_log(10, "CreateFile failed: 0x%08x", GetLastError());
                }
            }
        }
        else {
            debug_log(11, "SetupDiGetDeviceInterfaceDetail failed: 0x%08x", GetLastError());
        }

        free(detail);
        index++;
    }

    SetupDiDestroyDeviceInfoList(device_info);

    if (!stlink_found) {
        debug_log(12, "No working STLink device found");
        if (winusb_handle) WinUsb_Free(winusb_handle);
        if (device_handle) CloseHandle(device_handle);
        return -1;
    }

    debug_log(13, "USB initialization successful for device: %s", serial.c_str());
    return 0;
}

int STLinkServer::usb_close() {
    if (winusb_handle) {
        WinUsb_Free(winusb_handle);
        winusb_handle = NULL;
    }
    if (device_handle) {
        CloseHandle(device_handle);
        device_handle = NULL;
    }
    rx_ep = tx_ep = trace_ep = 0;
    return 0;
}

int STLinkServer::open_debug_interface(DebugInterface& iface) {
    iface.fw_major_ver = 2;
    iface.fw_jtag_ver = 0x1C;
    return 0;
}

int STLinkServer::handle_hotplug(bool arrived) {
    if (arrived) {
        int res = usb_close();
        if (res != 0) return res;
        res = usb_init();
        if (res != 0) return res;
        DebugInterface iface = { .swd_freq = 24000000, .target_voltage = 3 };
        return open_debug_interface(iface);
    }
    else {
        return usb_close();
    }
}

int STLinkServer::refresh_devices() {
    GUID winusb_guid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
    HDEVINFO device_info = SetupDiGetClassDevs(&winusb_guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (device_info == INVALID_HANDLE_VALUE) return -1;

    SP_DEVICE_INTERFACE_DATA interface_data = { sizeof(SP_DEVICE_INTERFACE_DATA) };
    DWORD index = 0;
    while (SetupDiEnumDeviceInterfaces(device_info, NULL, &winusb_guid, index, &interface_data)) {
        DWORD required_size;
        SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, NULL, 0, &required_size, NULL);
        PSP_DEVICE_INTERFACE_DETAIL_DATA detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, detail, required_size, NULL, NULL)) {
            device_key = STLINK_PID;
        }
        free(detail);
        index++;
    }
    SetupDiDestroyDeviceInfoList(device_info);
    return 0;
}

int STLinkServer::server_loop() {
    debug_log(18, "non_blocking_accept_main");
    debug_log(19, "Entering non_blocking_accept_main");

    time_t last_activity = time(NULL);

    while (true) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(server_socket, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        int activity = select(0, &readfds, NULL, NULL, &timeout);

        if (activity == SOCKET_ERROR) {
            return -1;
        }

        if (activity > 0 && FD_ISSET(server_socket, &readfds)) {
            SOCKET client_socket = accept(server_socket, NULL, NULL);
            if (client_socket != INVALID_SOCKET) {
                last_activity = time(NULL);
                closesocket(client_socket);
            }
        }

        if (auto_exit && difftime(time(NULL), last_activity) > 30) {
            debug_log(20, "No connections/data in the last 30 seconds. Exiting due to auto-exit.");
            return 0;
        }
    }

    return 0;
}

int STLinkServer::get_firmware_version(DebugInterface& iface) {
    uint8_t databuf[32];
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = {
        0x80,
        6,
        0x0300,
        0,
        32
    };
    if (WinUsb_ControlTransfer(winusb_handle, setup, databuf, 32, &bytes_transferred, NULL)) {
        iface.fw_major_ver = databuf[0];
        iface.fw_jtag_ver = databuf[2];
        return 0;
    }
    return GetLastError();
}

int STLinkServer::exit_jtag_mode() {
    uint8_t cmdbuf[32] = { CMD_ENTER_SWD, 0x21 };
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = { 0x40, 0, 0, 0, 32 };
    if (WinUsb_ControlTransfer(winusb_handle, setup, cmdbuf, 32, &bytes_transferred, NULL)) {
        return 0;
    }
    return GetLastError();
}

int STLinkServer::blink_led() {
    uint8_t cmdbuf[32] = { CMD_ENTER_SWD, 0x49 };
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = { 0x40, 0, 0, 0, 32 };
    if (WinUsb_ControlTransfer(winusb_handle, setup, cmdbuf, 32, &bytes_transferred, NULL)) {
        return 0;
    }
    return GetLastError();
}

int STLinkServer::erase_flash() {
    uint8_t cmdbuf[2] = { CMD_ERASE_FLASH, 0 };
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::write_flash(uint32_t address, uint8_t* data, uint32_t length) {
    if (length > 0xFFFF) return -1;
    uint8_t cmdbuf[512];
    cmdbuf[0] = CMD_WRITE_MEM;
    memcpy(&cmdbuf[1], &address, 4);
    memcpy(&cmdbuf[5], &length, 4);
    memcpy(&cmdbuf[9], data, length);
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 9 + length, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::enter_swd_mode() {
    uint8_t cmdbuf[2] = { CMD_ENTER_SWD, 0xA3 };
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::read_register(uint8_t reg_id, uint32_t& value) {
    uint8_t cmdbuf[2] = { CMD_READ_REG, reg_id };
    uint8_t databuf[4];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 4, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (bytes_transferred == 4 && databuf[0] == 0x00) {
        memcpy(&value, databuf, 4);
        return 0;
    }
    return -1;
}

int STLinkServer::write_register(uint8_t reg_id, uint32_t value) {
    uint8_t cmdbuf[6] = { CMD_WRITE_REG, reg_id };
    memcpy(&cmdbuf[2], &value, 4);
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 6, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::read_trace(uint8_t* buffer, uint32_t max_length, uint32_t& read_length) {
    ULONG bytes_transferred;
    if (WinUsb_ReadPipe(winusb_handle, trace_ep, buffer, max_length, &bytes_transferred, NULL)) {
        read_length = bytes_transferred;
        return 0;
    }
    return GetLastError();
}

int STLinkServer::start(int debug_level) {
    this->debug_level = debug_level;

    if (create_listening_sockets() != 0) {
        info_log("Failed to create listening sockets");
        return -1;
    }

    if (usb_init() != 0) {
        info_log("USB initialization failed - no STLink device found");
        closesocket(server_socket);
        return -2;
    }

    DebugInterface iface;
    if (get_firmware_version(iface) != 0) {
        info_log("Failed to communicate with STLink device");
        usb_close();
        closesocket(server_socket);
        return -3;
    }

    info_log("STLink Server ready - FW v%d.%d", iface.fw_major_ver, iface.fw_jtag_ver);
    return server_loop();
}