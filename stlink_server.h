#ifndef STLINK_SERVER_H
#define STLINK_SERVER_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winusb.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "winusb.lib")

class STLinkServer {
private:
    // Constants
    static const USHORT STLINK_VID = 0x0483;
    static const USHORT STLINK_PID = 0x3748;
    static const uint8_t CMD_GET_VERSION = 0xF1;
    static const uint8_t CMD_ENTER_SWD = 0xF2;
    static const uint8_t CMD_WRITE_MEM = 0xF3;
    static const uint8_t CMD_ERASE_FLASH = 0xF4;
    static const uint8_t CMD_READ_REG = 0xF5;
    static const uint8_t CMD_WRITE_REG = 0xF6;

    // Data members
    HANDLE device_handle;                // Windows device handle
    WINUSB_INTERFACE_HANDLE winusb_handle; // WinUSB handle
    SOCKET server_socket;                // Server socket
    HANDLE server_thread;                // Server thread handle
    uint32_t device_key;                 // Device identifier
    std::string serial;                  // Device serial number
    UCHAR rx_ep;                         // Receive endpoint
    UCHAR tx_ep;                         // Transmit endpoint
    UCHAR trace_ep;                      // Trace endpoint

public:
    // Nested structure for debug interface
    struct DebugInterface {
        uint32_t swd_freq;
        uint8_t target_voltage;
        uint8_t fw_major_ver;
        uint8_t fw_jtag_ver;
    };

    // Constructor and destructor
    STLinkServer();
    ~STLinkServer();

    // Public methods
    int start();
    int usb_init();
    int usb_close();
    int open_debug_interface(DebugInterface& iface);
    int handle_hotplug(bool arrived);
    int refresh_devices();
    int server_loop();
    int get_firmware_version(DebugInterface& iface);
    int exit_jtag_mode();
    int blink_led();
    int erase_flash();
    int write_flash(uint32_t address, uint8_t* data, uint32_t length);
    int enter_swd_mode();
    int read_register(uint8_t reg_id, uint32_t& value);
    int write_register(uint8_t reg_id, uint32_t value);
    int read_trace(uint8_t* buffer, uint32_t max_length, uint32_t& read_length);
};

#endif