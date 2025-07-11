#define WIN32_LEAN_AND_MEAN
#include "stlink_server.h"
#include <stdexcept>
#include <vector>

STLinkServer::STLinkServer()
    : device_handle(NULL),
    winusb_handle(NULL),
    server_socket(INVALID_SOCKET),
    server_thread(NULL),
    device_key(0),
    serial(64, '\0'),
    rx_ep(0),
    tx_ep(0),
    trace_ep(0) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
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
    WSACleanup();
}

int STLinkServer::usb_init() {
    GUID winusb_guid = { 0xA5DCBF10, 0x6530, 0x11D2, {0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED} };
    HDEVINFO device_info = SetupDiGetClassDevs(&winusb_guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (device_info == INVALID_HANDLE_VALUE) return -1;

    SP_DEVICE_INTERFACE_DATA interface_data = { sizeof(SP_DEVICE_INTERFACE_DATA) };
    SP_DEVINFO_DATA devinfo_data = { sizeof(SP_DEVINFO_DATA) };
    DWORD index = 0;
    BOOL found = FALSE;

    while (SetupDiEnumDeviceInterfaces(device_info, NULL, &winusb_guid, index, &interface_data)) {
        DWORD required_size;
        SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, NULL, 0, &required_size, NULL);
        PSP_DEVICE_INTERFACE_DETAIL_DATA detail = (PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(required_size);
        detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);
        if (SetupDiGetDeviceInterfaceDetail(device_info, &interface_data, detail, required_size, NULL, &devinfo_data)) {
            device_handle = CreateFile(detail->DevicePath, GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED, NULL);
            if (device_handle != INVALID_HANDLE_VALUE) {
                if (WinUsb_Initialize(device_handle, &winusb_handle)) {
                    // Parse configuration descriptor to get endpoints
                    UCHAR config_descriptor[512];
                    ULONG bytes_transferred;
                    if (WinUsb_GetDescriptor(winusb_handle, USB_CONFIGURATION_DESCRIPTOR_TYPE, 0, 0,
                        config_descriptor, sizeof(config_descriptor), &bytes_transferred)) {
                        // Simplified parsing: iterate through descriptor to find endpoints
                        USB_CONFIGURATION_DESCRIPTOR* config = (USB_CONFIGURATION_DESCRIPTOR*)config_descriptor;
                        UCHAR* ptr = config_descriptor + config->bLength;
                        UCHAR* end = config_descriptor + config->wTotalLength;
                        while (ptr < end) {
                            USB_COMMON_DESCRIPTOR* desc = (USB_COMMON_DESCRIPTOR*)ptr;
                            if (desc->bDescriptorType == USB_ENDPOINT_DESCRIPTOR_TYPE) {
                                USB_ENDPOINT_DESCRIPTOR* ep = (USB_ENDPOINT_DESCRIPTOR*)desc;
                                if (ep->bmAttributes == USB_ENDPOINT_TYPE_BULK) {
                                    if (ep->bEndpointAddress & USB_ENDPOINT_DIRECTION_MASK) {
                                        rx_ep = ep->bEndpointAddress; // Bulk IN
                                    }
                                    else {
                                        tx_ep = ep->bEndpointAddress; // Bulk OUT
                                    }
                                }
                                else if (ep->bmAttributes == USB_ENDPOINT_TYPE_INTERRUPT &&
                                    (ep->bEndpointAddress & USB_ENDPOINT_DIRECTION_MASK)) {
                                    trace_ep = ep->bEndpointAddress; // Interrupt IN
                                }
                            }
                            ptr += desc->bLength;
                        }
                        found = (rx_ep && tx_ep); // Ensure at least bulk endpoints are found
                    }
                    if (found) {
                        free(detail);
                        break;
                    }
                    WinUsb_Free(winusb_handle);
                    winusb_handle = NULL;
                }
                CloseHandle(device_handle);
                device_handle = NULL;
            }
        }
        free(detail);
        index++;
    }
    SetupDiDestroyDeviceInfoList(device_info);
    return found ? 0 : -1;
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
    return 0; // WinUSB interface is already claimed in usb_init
}

int STLinkServer::handle_hotplug(bool arrived) {
    if (arrived) {
        int res = usb_close(); // Close any existing connection
        if (res != 0) return res;
        res = usb_init(); // Reinitialize
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
            device_key = STLINK_PID; // Simplified; actual VID/PID check requires parsing
        }
        free(detail);
        index++;
    }
    SetupDiDestroyDeviceInfoList(device_info);
    return 0;
}

int STLinkServer::server_loop() {
    return 0; // Placeholder
}

int STLinkServer::get_firmware_version(DebugInterface& iface) {
    uint8_t databuf[32];
    ULONG bytes_transferred;
    WINUSB_SETUP_PACKET setup = {
        0x80, // Device-to-Host, Standard
        6,    // GET_DESCRIPTOR
        0x0300, // String descriptor
        0,    // Index
        32    // Length
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
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
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
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
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
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
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
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 4, &bytes_transferred, NULL)) {
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
    if (!WinUsb_ReadPipe(winusb_handle, rx_ep, databuf, 2, &bytes_transferred, NULL)) {
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

int STLinkServer::start() {
    if (usb_init() != 0) return -1;
    DebugInterface iface = { .swd_freq = 24000000, .target_voltage = 3 };
    if (open_debug_interface(iface) != 0) return -1;
    return server_loop();
}