#ifndef STLINK_SERVER_H
#define STLINK_SERVER_H

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winusb.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <cstdarg>
#include <regex>
#include <fstream>
#include <unordered_map>

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
    static const uint8_t CMD_MASS_ERASE = 0xF7;
    static const uint8_t CMD_READ_MEM = 0xF8;
    static const uint8_t CMD_STEP = 0xFA;
    static const uint8_t CMD_CONTINUE = 0xFB;
    static const uint8_t CMD_HALT = 0xFC;
    static const uint8_t CMD_SET_BREAKPOINT = 0xFD;
    static const uint8_t CMD_REMOVE_BREAKPOINT = 0xFE;
    static const uint8_t CMD_READ_ALL_REGS = 0xFF;

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
    int debug_level;                     // Debug verbosity level
    int debug_counter;                   // Debug message counter
    int port;                            // TCP listening port
    bool auto_exit;                      // Auto-exit when no clients
    std::ofstream log_file;              // Log file stream
    bool target_halted;
    uint32_t halted_pc;
    std::unordered_map<uint32_t, uint8_t> breakpoints;

    // Private methods
    std::string extract_serial_number(const WCHAR* device_path);
    void debug_log(int level, const char* format, ...);
    void info_log(const char* format, ...);
    void stlk_log(const char* format, ...);
    int create_listening_sockets();
    int read_memory(uint32_t address, uint8_t* data, uint32_t length);
    int write_memory(uint32_t address, const uint8_t* data, uint32_t length);

    int continue_execution();
    int halt_target();


public:
    // Nested structure for debug interface
    struct DebugInterface {
        uint32_t swd_freq;
        uint8_t target_voltage;
        uint8_t fw_major_ver;
        uint8_t fw_jtag_ver;
    };

    // Constructor and destructor
    STLinkServer(int port = 7184, bool auto_exit = false, const std::string& log_file_path = "");
    ~STLinkServer();

    // Public methods
    int start(int debug_level = 0);
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
    int write_flash(uint32_t address, const uint8_t* data, uint32_t length);
    int enter_swd_mode();
    int read_register(uint8_t reg_id, uint32_t& value);
    int write_register(uint8_t reg_id, uint32_t value);
    int read_trace(uint8_t* buffer, uint32_t max_length, uint32_t& read_length);
    int program_firmware(const std::vector<uint8_t>& firmware_data, uint32_t base_address);
    int verify_firmware(const std::vector<uint8_t>& firmware_data, uint32_t base_address);
    int read_flash(uint32_t address, uint8_t* data, uint32_t length);
    int mass_erase();
    int debug_read_memory(uint32_t address, uint8_t* data, uint32_t length);
    int debug_write_memory(uint32_t address, uint8_t* data, uint32_t length);
    int debug_set_breakpoint(uint32_t address, bool hardware);
    int debug_remove_breakpoint(uint32_t address, bool hardware);
    int debug_step();
    int debug_continue();
    int debug_halt();
    int debug_read_registers(uint32_t* registers, size_t count);
    int debug_write_register(uint8_t reg_num, uint32_t value);
    int debug_read_register(uint8_t reg_num, uint32_t* value);
    int set_breakpoint(uint32_t address, bool hardware);
    int remove_breakpoint(uint32_t address);
    int single_step();
    int read_all_registers(uint32_t* registers, size_t count);
};

#endif

