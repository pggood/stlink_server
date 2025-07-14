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
        throw std::runtime_error("WSAStartup failed with error: " + std::to_string(WSAGetLastError()));
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
    debug_log(1, "Entering create_listening_sockets()");
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
        debug_log(1, "getaddrinfo failed with error: %d", iResult);
        return -1;
    }

    for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
        server_socket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (server_socket == INVALID_SOCKET) {
            debug_log(1, "socket creation failed with error: %d", WSAGetLastError());
            continue;
        }

        iResult = bind(server_socket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            debug_log(1, "bind failed with error: %d", WSAGetLastError());
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

        u_long iMode = 1;
        iResult = ioctlsocket(server_socket, FIONBIO, &iMode);
        if (iResult != NO_ERROR) {
            debug_log(1, "ioctlsocket failed with error: %d", iResult);
            closesocket(server_socket);
            server_socket = INVALID_SOCKET;
            continue;
        }

        break;
    }

    freeaddrinfo(result);
    if (server_socket == INVALID_SOCKET) {
        debug_log(1, "No valid socket created");
        return -1;
    }

    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        debug_log(1, "listen failed with error: %d", WSAGetLastError());
        closesocket(server_socket);
        server_socket = INVALID_SOCKET;
        return -1;
    }

    debug_log(1, "create_listening_sockets completed successfully");
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
    debug_log(1, "Entering usb_init");
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
            debug_log(1, "Memory allocation failed for device interface detail");
            SetupDiDestroyDeviceInfoList(device_info);
            return -1;
        }

        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        SP_DEVINFO_DATA devinfo_data = { sizeof(SP_DEVINFO_DATA) };

        if (SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, detail, required_size, NULL, &devinfo_data)) {
            if (wcsstr(detail->DevicePath, L"vid_0483") && wcsstr(detail->DevicePath, L"pid_3748")) {
                debug_log(2, "Found STLink device with VID=0483, PID=3748");
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
                                    debug_log(1, "Communication test failed: 0x%08x", GetLastError());
                                }
                            }
                            else {
                                debug_log(1, "Missing required endpoints");
                            }
                        }
                        else {
                            debug_log(1, "QueryInterfaceSettings failed: 0x%08x", GetLastError());
                        }
                    }
                    else {
                        debug_log(1, "WinUsb_Initialize failed: 0x%08x", GetLastError());
                    }

                    if (!stlink_found) {
                        if (winusb_handle) WinUsb_Free(winusb_handle);
                        CloseHandle(device_handle);
                        winusb_handle = NULL;
                        device_handle = NULL;
                    }
                }
                else {
                    debug_log(1, "CreateFile failed: 0x%08x", GetLastError());
                }
            }
        }
        else {
            debug_log(1, "SetupDiGetDeviceInterfaceDetail failed: 0x%08x", GetLastError());
        }

        free(detail);
        index++;
    }

    SetupDiDestroyDeviceInfoList(device_info);

    if (!stlink_found) {
        debug_log(1, "No working STLink device found");
        return -1;
    }

    debug_log(1, "USB initialization successful for device: %s", serial.c_str());
    return 0;
}

int STLinkServer::usb_close() {
    debug_log(1, "Closing USB device");
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
    debug_log(1, "Opening debug interface");
    iface.fw_major_ver = 2;
    iface.fw_jtag_ver = 0x1C;
    return 0;
}

int STLinkServer::handle_hotplug(bool arrived) {
    debug_log(1, "Handling hotplug event: %s", arrived ? "arrival" : "removal");
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
    debug_log(1, "Refreshing devices");
    GUID winusb_guid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
    HDEVINFO device_info = SetupDiGetClassDevs(&winusb_guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (device_info == INVALID_HANDLE_VALUE) {
        debug_log(1, "SetupDiGetClassDevs failed in refresh_devices: 0x%08x", GetLastError());
        return -1;
    }

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
    debug_log(1, "Entering server_loop");
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
            debug_log(1, "select failed with error: %d", WSAGetLastError());
            return -1;
        }

        if (activity > 0 && FD_ISSET(server_socket, &readfds)) {
            debug_log(2, "Accepting new client connection");
            SOCKET client_socket = accept(server_socket, NULL, NULL);
            if (client_socket != INVALID_SOCKET) {
                last_activity = time(NULL);
                debug_log(2, "Client connected, socket: %d", client_socket);
                closesocket(client_socket);
            }
            else {
                debug_log(1, "accept failed with error: %d", WSAGetLastError());
            }
        }

        if (auto_exit && difftime(time(NULL), last_activity) > 30) {
            debug_log(1, "No connections/data in the last 30 seconds. Exiting due to auto-exit.");
            return 0;
        }
    }

    debug_log(1, "Exiting server_loop");
    return 0;
}

int STLinkServer::get_firmware_version(DebugInterface& iface) {
    debug_log(1, "Getting firmware version");
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
        debug_log(1, "Firmware version retrieved: v%d.%d", iface.fw_major_ver, iface.fw_jtag_ver);
        return 0;
    }
    debug_log(1, "WinUsb_ControlTransfer failed: 0x%08x", GetLastError());
    return GetLastError();
}
// Add to stlink_server.cpp
int STLinkServer::write_flash(uint32_t address, const uint8_t* data, uint32_t length) {
    debug_log(1, "Writing flash at address 0x%08x, length %u", address, length);

    if (length > 0xFFFF) {
        debug_log(1, "Flash write length too large: %u", length);
        return -1;
    }

    // Check if address is in flash memory range
    if (address < 0x08000000 || address >= 0x08200000) {
        debug_log(1, "Invalid flash address: 0x%08x", address);
        return -1;
    }

    // Check alignment (STM32 typically requires 32-bit alignment)
    if ((address % 4) != 0 || (length % 4) != 0) {
        debug_log(1, "Unaligned flash access: addr=0x%08x, len=%u", address, length);
        return -1;
    }

    uint8_t cmdbuf[512];
    cmdbuf[0] = CMD_WRITE_MEM;
    memcpy(&cmdbuf[1], &address, 4);
    memcpy(&cmdbuf[5], &length, 4);
    memcpy(&cmdbuf[9], data, length);

    uint8_t databuf[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 9 + length, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_WritePipe failed: 0x%08x", err);
        return err;
    }

    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", err);
        return err;
    }

    if (bytes_transferred != 2 || databuf[0] != 0x00) {
        debug_log(1, "Flash write verification failed");
        return -1;
    }

    return 0;
}
// Add to stlink_server.cpp

int STLinkServer::mass_erase() {
    debug_log(1, "Performing mass erase");
    uint8_t cmdbuf[2] = { CMD_MASS_ERASE, 0x00 };
    uint8_t databuf[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "Mass erase command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "Mass erase response failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred != 2 || databuf[0] != 0x00) {
        debug_log(1, "Mass erase verification failed");
        return -1;
    }

    return 0;
}

int STLinkServer::read_flash(uint32_t address, uint8_t* data, uint32_t length) {
    debug_log(1, "Reading flash at address 0x%08x, length %u", address, length);

    if (length > 0xFFFF) {
        debug_log(1, "Flash read length too large: %u", length);
        return -1;
    }

    uint8_t cmdbuf[5] = { CMD_READ_MEM };
    memcpy(&cmdbuf[1], &address, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 5, &bytes_transferred, NULL)) {
        debug_log(1, "Flash read command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, data, length, &bytes_transferred, NULL)) {
        debug_log(1, "Flash read data failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred != length) {
        debug_log(1, "Incomplete flash read: expected %u, got %u", length, bytes_transferred);
        return -1;
    }

    return 0;
}

int STLinkServer::program_firmware(const std::vector<uint8_t>& firmware_data, uint32_t base_address) {
    debug_log(1, "Programming firmware (size: %zu bytes) to address 0x%08x",
        firmware_data.size(), base_address);

    // Check for size overflow
    if (firmware_data.size() > UINT32_MAX) {
        debug_log(1, "Firmware size too large: %zu bytes exceeds UINT32_MAX", firmware_data.size());
        return -1;
    }

    // First perform mass erase
    int res = mass_erase();
    if (res != 0) {
        debug_log(1, "Mass erase failed before programming");
        return res;
    }

    // Program in chunks (STLink typically handles up to 1024 bytes at a time)
    const size_t chunk_size = 1024;
    size_t remaining = firmware_data.size();
    size_t offset = 0;

    while (remaining > 0) {
        uint32_t current_chunk = static_cast<uint32_t>((remaining > chunk_size) ? chunk_size : remaining);
        uint32_t current_address = base_address + static_cast<uint32_t>(offset);

        res = write_flash(current_address, &firmware_data[offset], current_chunk);
        if (res != 0) {
            debug_log(1, "Flash write failed at offset 0x%08x", offset);
            return res;
        }

        offset += current_chunk;
        remaining -= current_chunk;
    }

    return 0;
}

int STLinkServer::verify_firmware(const std::vector<uint8_t>& firmware_data, uint32_t base_address) {
    debug_log(1, "Verifying firmware (size: %zu bytes) at address 0x%08x",
        firmware_data.size(), base_address);

    // Check for size overflow
    if (firmware_data.size() > UINT32_MAX) {
        debug_log(1, "Firmware size too large: %zu bytes exceeds UINT32_MAX", firmware_data.size());
        return -1;
    }

    // Read back in chunks
    const size_t chunk_size = 1024;
    size_t remaining = firmware_data.size();
    size_t offset = 0;
    std::vector<uint8_t> read_buffer(chunk_size);

    while (remaining > 0) {
        uint32_t current_chunk = static_cast<uint32_t>((remaining > chunk_size) ? chunk_size : remaining);
        uint32_t current_address = base_address + static_cast<uint32_t>(offset);

        int res = read_flash(current_address, read_buffer.data(), current_chunk);
        if (res != 0) {
            debug_log(1, "Flash read failed at offset 0x%08x", offset);
            return res;
        }

        // Compare with original data
        if (memcmp(read_buffer.data(), &firmware_data[offset], current_chunk) != 0) {
            debug_log(1, "Verification failed at offset 0x%08x", offset);
            return -1;
        }

        offset += current_chunk;
        remaining -= current_chunk;
    }

    return 0;
}

int STLinkServer::exit_jtag_mode() {
    debug_log(1, "Exiting JTAG mode");
    uint8_t cmdbuf[32] = { CMD_ENTER_SWD, 0x21 };
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = { 0x40, 0, 0, 0, 32 };
    if (WinUsb_ControlTransfer(winusb_handle, setup, cmdbuf, 32, &bytes_transferred, NULL)) {
        return 0;
    }
    debug_log(1, "WinUsb_ControlTransfer failed: 0x%08x", GetLastError());
    return GetLastError();
}

int STLinkServer::blink_led() {
    debug_log(1, "Blinking LED");
    uint8_t cmdbuf[32] = { CMD_ENTER_SWD, 0x49 };
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = { 0x40, 0, 0, 0, 32 };
    if (WinUsb_ControlTransfer(winusb_handle, setup, cmdbuf, 32, &bytes_transferred, NULL)) {
        return 0;
    }
    debug_log(1, "WinUsb_ControlTransfer failed: 0x%08x", GetLastError());
    return GetLastError();
}

int STLinkServer::erase_flash() {
    debug_log(1, "Erasing flash");
    uint8_t cmdbuf[2] = { CMD_ERASE_FLASH, 0 };
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_WritePipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}


int STLinkServer::enter_swd_mode() {
    debug_log(1, "Entering SWD mode");
    uint8_t cmdbuf[2] = { CMD_ENTER_SWD, 0xA3 };
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_WritePipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::read_register(uint8_t reg_id, uint32_t& value) {
    debug_log(1, "Reading register %u", reg_id);
    uint8_t cmdbuf[2] = { CMD_READ_REG, reg_id };
    uint8_t databuf[4];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_WritePipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 4, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    if (bytes_transferred == 4 && databuf[0] == 0x00) {
        memcpy(&value, databuf, 4);
        return 0;
    }
    debug_log(1, "Register read failed: bytes_transferred=%u, databuf[0]=0x%02x", bytes_transferred, databuf[0]);
    return -1;
}

int STLinkServer::write_register(uint8_t reg_id, uint32_t value) {
    debug_log(1, "Writing register %u with value 0x%08x", reg_id, value);
    uint8_t cmdbuf[6] = { CMD_WRITE_REG, reg_id };
    memcpy(&cmdbuf[2], &value, 4);
    uint8_t databuf[2];
    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 6, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_WritePipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, (PUCHAR)databuf, 2, &bytes_transferred, NULL)) {
        debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", GetLastError());
        return GetLastError();
    }
    return (bytes_transferred == 2 && databuf[0] == 0x00) ? 0 : -1;
}

int STLinkServer::read_trace(uint8_t* buffer, uint32_t max_length, uint32_t& read_length) {
    debug_log(1, "Reading trace with max_length %u", max_length);
    ULONG bytes_transferred;
    if (WinUsb_ReadPipe(winusb_handle, trace_ep, buffer, max_length, &bytes_transferred, NULL)) {
        read_length = bytes_transferred;
        debug_log(1, "Trace read successful, bytes_transferred: %u", bytes_transferred);
        return 0;
    }
    debug_log(1, "WinUsb_ReadPipe failed: 0x%08x", GetLastError());
    return GetLastError();
}
// Add to stlink_server.cpp
int STLinkServer::debug_read_memory(uint32_t address, uint8_t* data, uint32_t length) {
    if (target_halted) {
        return read_memory(address, data, length);
    }
    else {
        // For running target, we need to halt first
        int res = halt_target();
        if (res != 0) return res;
        res = read_memory(address, data, length);
        continue_execution(); // Resume after read
        return res;
    }
}
int STLinkServer::read_memory(uint32_t address, uint8_t* data, uint32_t length) {
    debug_log(1, "Reading memory at address 0x%08x, length %u", address, length);

    uint8_t cmdbuf[5] = { CMD_READ_MEM };
    memcpy(&cmdbuf[1], &address, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, sizeof(cmdbuf), &bytes_transferred, NULL)) {
        debug_log(1, "Read memory command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, data, length, &bytes_transferred, NULL)) {
        debug_log(1, "Read memory data failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred != length) {
        debug_log(1, "Incomplete memory read: expected %u, got %u", length, bytes_transferred);
        return -1;
    }

    return 0;
}

int STLinkServer::write_memory(uint32_t address, const uint8_t* data, uint32_t length) {
    debug_log(1, "Writing memory at address 0x%08x, length %u", address, length);

    uint8_t cmdbuf[9] = { CMD_WRITE_MEM };
    memcpy(&cmdbuf[1], &address, 4);
    memcpy(&cmdbuf[5], &length, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, sizeof(cmdbuf), &bytes_transferred, NULL)) {
        debug_log(1, "Write memory command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, const_cast<PUCHAR>(data), length, &bytes_transferred, NULL)) {
        debug_log(1, "Write memory data failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    uint8_t response[2];
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        debug_log(1, "Write memory response failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred != 2 || response[0] != 0x00) {
        debug_log(1, "Memory write verification failed");
        return -1;
    }

    return 0;
}
int STLinkServer::set_breakpoint(uint32_t address, bool hardware) {
    debug_log(1, "Setting %s breakpoint at address 0x%08x", hardware ? "hardware" : "software", address);

    if (!hardware) {
        debug_log(1, "Software breakpoints not supported");
        return -1; // Software breakpoints require instruction modification, not implemented here
    }

    // Check if address is in valid flash or RAM range
    if ((address < 0x08000000 || address >= 0x08200000) && (address < 0x20000000 || address >= 0x20010000)) {
        debug_log(1, "Invalid breakpoint address: 0x%08x", address);
        return -1;
    }

    // Ensure 2-byte alignment for Thumb instructions
    if (address % 2 != 0) {
        debug_log(1, "Unaligned breakpoint address: 0x%08x", address);
        return -1;
    }

    // Command to set hardware breakpoint (assuming FPB unit for Cortex-M)
    uint8_t cmdbuf[16];
    cmdbuf[0] = CMD_SET_BREAKPOINT;
    cmdbuf[1] = 0x01; // Hardware breakpoint
    memcpy(&cmdbuf[2], &address, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 6, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_WritePipe failed for breakpoint: 0x%08x", err);
        return err;
    }

    uint8_t response[2];
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, response, 2, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_ReadPipe failed for breakpoint: 0x%08x", err);
        return err;
    }

    if (bytes_transferred != 2 || response[0] != 0x00) {
        debug_log(1, "Breakpoint set failed at 0x%08x", address);
        return -1;
    }

    return 0;
}

int STLinkServer::remove_breakpoint(uint32_t address) {
    debug_log(1, "Removing breakpoint at address 0x%08x", address);

    // Check address validity
    if ((address < 0x08000000 || address >= 0x08200000) && (address < 0x20000000 || address >= 0x20010000)) {
        debug_log(1, "Invalid breakpoint address: 0x%08x", address);
        return -1;
    }

    // Ensure 2-byte alignment
    if (address % 2 != 0) {
        debug_log(1, "Unaligned breakpoint address: 0x%08x", address);
        return -1;
    }

    // Command to remove hardware breakpoint
    uint8_t cmdbuf[16];
    cmdbuf[0] = CMD_REMOVE_BREAKPOINT;
    memcpy(&cmdbuf[1], &address, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 5, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_WritePipe failed for breakpoint removal: 0x%08x", err);
        return err;
    }

    uint8_t response[2];
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, response, 2, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_ReadPipe failed for breakpoint removal: 0x%08x", err);
        return err;
    }

    if (bytes_transferred != 2 || response[0] != 0x00) {
        debug_log(1, "Breakpoint removal failed at 0x%08x", address);
        return -1;
    }

    return 0;
}
int STLinkServer::single_step() {
    debug_log(1, "Performing single-step");

    // Enable single-step mode via DHCSR (Debug Halting Control and Status Register)
    uint32_t dhcsr_addr = 0xE000EDF0; // Cortex-M DHCSR address
    uint32_t dhcsr_value = (1 << 0) | (1 << 1); // C_DEBUGEN | C_STEP

    uint8_t cmdbuf[16];
    cmdbuf[0] = CMD_WRITE_REG;
    memcpy(&cmdbuf[1], &dhcsr_addr, 4);
    memcpy(&cmdbuf[5], &dhcsr_value, 4);

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 9, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_WritePipe failed for single-step: 0x%08x", err);
        return err;
    }

    // Wait for step completion
    uint8_t response[2];
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, response, 2, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_ReadPipe failed for single-step: 0x%08x", err);
        return err;
    }

    if (bytes_transferred != 2 || response[0] != 0x00) {
        debug_log(1, "Single-step failed");
        return -1;
    }

    return 0;
}
int STLinkServer::read_all_registers(uint32_t* registers, size_t count) {
    debug_log(1, "Reading %zu registers", count);

    // Assume Cortex-M has 16 core registers (R0-R15) + special registers (e.g., PSR)
    if (count < 17) {
        debug_log(1, "Insufficient buffer size for registers: %zu", count);
        return -1;
    }

    // Command to read all registers
    uint8_t cmdbuf[16];
    cmdbuf[0] = CMD_READ_ALL_REGS;

    ULONG bytes_transferred;
    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, 1, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_WritePipe failed for read registers: 0x%08x", err);
        return err;
    }

    // Expect 68 bytes (17 registers * 4 bytes)
    uint8_t response[68];
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, response, 68, &bytes_transferred, NULL)) {
        DWORD err = GetLastError();
        debug_log(1, "WinUsb_ReadPipe failed for read registers: 0x%08x", err);
        return err;
    }

    if (bytes_transferred != 68) {
        debug_log(1, "Incomplete register data received: %lu bytes", bytes_transferred);
        return -1;
    }

    // Copy response to output buffer
    for (size_t i = 0; i < 17; i++) {
        registers[i] = (response[i * 4] << 24) | (response[i * 4 + 1] << 16) |
            (response[i * 4 + 2] << 8) | response[i * 4 + 3];
    }

    return 0;
}

int STLinkServer::halt_target() {
    debug_log(1, "Halting target");
    uint8_t cmdbuf[2] = { CMD_HALT, 0x00 };
    uint8_t response[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, sizeof(cmdbuf), &bytes_transferred, NULL) ||
        !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        debug_log(1, "Halt command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred == 2 && response[0] == 0x00) {
        target_halted = true;
        // Read PC at halt
        uint32_t pc;
        if (read_register(15, pc) == 0) {
            halted_pc = pc;
        }
        return 0;
    }

    return -1;
}

int STLinkServer::continue_execution() {
    debug_log(1, "Continuing execution");
    uint8_t cmdbuf[2] = { CMD_CONTINUE, 0x00 };
    uint8_t response[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmdbuf, sizeof(cmdbuf), &bytes_transferred, NULL) ||
        !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        debug_log(1, "Continue command failed: 0x%08x", GetLastError());
        return GetLastError();
    }

    if (bytes_transferred == 2 && response[0] == 0x00) {
        target_halted = false;
        return 0;
    }

    return -1;
}
int STLinkServer::debug_write_memory(uint32_t address, uint8_t* data, uint32_t length) {
    if (target_halted) {
        return write_memory(address, data, length);
    }
    else {
        int res = halt_target();
        if (res != 0) return res;
        res = write_memory(address, data, length);
        continue_execution();
        return res;
    }
}

int STLinkServer::debug_set_breakpoint(uint32_t address, bool hardware) {
    if (hardware) {
        // Use hardware breakpoint
        uint8_t cmd[5] = { CMD_WRITE_REG };
        uint32_t value = address | 0x1; // Set breakpoint
        memcpy(&cmd[1], &value, 4);

        uint8_t response[2];
        ULONG bytes_transferred;
        if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmd, sizeof(cmd), &bytes_transferred, NULL) ||
            !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
            return GetLastError();
        }
        return (bytes_transferred == 2 && response[0] == 0x00) ? 0 : -1;
    }
    else {
        // Software breakpoint - replace instruction with BKPT
        uint8_t original[2];
        int res = read_memory(address, original, 2);
        if (res != 0) return res;

        uint8_t bkpt[2] = { 0xBE, 0x00 }; // ARM BKPT #0 instruction
        res = write_memory(address, bkpt, 2);
        if (res != 0) return res;

        breakpoints[address] = original[0];
        breakpoints[address + 1] = original[1];
        return 0;
    }
}

int STLinkServer::debug_remove_breakpoint(uint32_t address, bool hardware) {
    if (hardware) {
        // Remove hardware breakpoint
        uint8_t cmd[5] = { CMD_WRITE_REG };
        uint32_t value = 0; // Clear breakpoint
        memcpy(&cmd[1], &value, 4);

        uint8_t response[2];
        ULONG bytes_transferred;
        if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmd, sizeof(cmd), &bytes_transferred, NULL) ||
            !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
            return GetLastError();
        }
        return (bytes_transferred == 2 && response[0] == 0x00) ? 0 : -1;
    }
    else {
        // Restore original instruction
        auto it1 = breakpoints.find(address);
        auto it2 = breakpoints.find(address + 1);
        if (it1 == breakpoints.end() || it2 == breakpoints.end()) {
            return -1; // Breakpoint not found
        }

        uint8_t original[2] = { it1->second, it2->second };
        int res = write_memory(address, original, 2);
        if (res == 0) {
            breakpoints.erase(it1);
            breakpoints.erase(it2);
        }
        return res;
    }
}

int STLinkServer::debug_step() {
    if (!target_halted) return 0; // Already running

    uint8_t cmd[2] = { CMD_STEP, 0x00 };
    uint8_t response[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmd, sizeof(cmd), &bytes_transferred, NULL) ||
        !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        return GetLastError();
    }

    if (bytes_transferred == 2 && response[0] == 0x00) {
        // Read PC after step
        uint32_t pc;
        if (read_register(15, pc) == 0) {
            halted_pc = pc;
        }
        return 0;
    }
    return -1;
}

int STLinkServer::debug_continue() {
    if (!target_halted) return 0; // Already running

    uint8_t cmd[2] = { CMD_CONTINUE, 0x00 };
    uint8_t response[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmd, sizeof(cmd), &bytes_transferred, NULL) ||
        !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        return GetLastError();
    }

    if (bytes_transferred == 2 && response[0] == 0x00) {
        target_halted = false;
        return 0;
    }
    return -1;
}

int STLinkServer::debug_halt() {
    if (target_halted) return 0; // Already halted

    uint8_t cmd[2] = { CMD_HALT, 0x00 };
    uint8_t response[2];
    ULONG bytes_transferred;

    if (!WinUsb_WritePipe(winusb_handle, tx_ep, cmd, sizeof(cmd), &bytes_transferred, NULL) ||
        !WinUsb_ReadPipe(winusb_handle, rx_ep, response, sizeof(response), &bytes_transferred, NULL)) {
        return GetLastError();
    }

    if (bytes_transferred == 2 && response[0] == 0x00) {
        target_halted = true;
        // Read PC at halt
        uint32_t pc;
        if (read_register(15, pc) == 0) {
            halted_pc = pc;
        }
        return 0;
    }
    return -1;
}

int STLinkServer::debug_read_registers(uint32_t* registers, size_t count) {
    if (count < 16) return -1; // ARM has 16 core registers

    for (int i = 0; i < 16; i++) {
        int res = read_register(i, registers[i]);
        if (res != 0) return res;
    }
    return 0;
}

int STLinkServer::debug_write_register(uint8_t reg_num, uint32_t value) {
    return write_register(reg_num, value);
}

int STLinkServer::debug_read_register(uint8_t reg_num, uint32_t* value) {
    return read_register(reg_num, *value);
}
int STLinkServer::start(int debug_level) {
    this->debug_level = debug_level;
    debug_log(1, "Starting STLinkServer with debug level %d", debug_level);

    if (create_listening_sockets() != 0) {
        info_log("Failed to create listening sockets");
        return -1;
    }
    debug_log(1, "Listening sockets created successfully");

    if (usb_init() != 0) {
        info_log("USB initialization failed - no STLink device found, continuing without device");
        // Continue instead of exiting
    }
    else {
        debug_log(1, "USB initialization completed");
        DebugInterface iface;
        if (get_firmware_version(iface) != 0) {
            info_log("Failed to communicate with STLink device");
            usb_close();
            closesocket(server_socket);
            return -3;
        }
        debug_log(1, "Firmware version check completed");
        info_log("STLink Server ready - FW v%d.%d", iface.fw_major_ver, iface.fw_jtag_ver);
    }

    debug_log(1, "Proceeding to server loop");
    return server_loop();
}