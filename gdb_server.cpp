// gdb_server.cpp
#include "gdb_server.h"
#include "stlink_server.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <string>
#include <vector>
#include <unordered_map>
using std::string;
using std::vector;
using std::stringstream;
using std::hex;
using std::setw;
using std::setfill;

// Helper function to split strings
std::vector<std::string> split(const std::string& s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}

// Helper function to calculate checksum
std::string checksum(const std::string& data) {
    uint8_t sum = 0;
    for (char c : data) {
        sum += c;
    }
    char buf[3];
    snprintf(buf, sizeof(buf), "%02x", sum);
    return buf;
}

GDBServer::GDBServer(int port)
    : m_port(port), m_serverSocket(INVALID_SOCKET), m_running(false) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        throw std::runtime_error("WSAStartup failed");
    }
}

GDBServer::~GDBServer() {
    stop();
    WSACleanup();
}

bool GDBServer::start() {
    if (m_running) return true;

    // Create server socket
    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket: " << WSAGetLastError() << std::endl;
        return false;
    }

    // Bind socket
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(m_port);

    if (bind(m_serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        std::cerr << "Bind failed: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        return false;
    }

    // Listen
    if (listen(m_serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen failed: " << WSAGetLastError() << std::endl;
        closesocket(m_serverSocket);
        return false;
    }

    m_running = true;
    m_serverThread = std::thread(&GDBServer::serverThread, this);
    return true;
}

void GDBServer::stop() {
    if (!m_running) return;

    m_running = false;

    // Shutdown server socket to unblock accept
    shutdown(m_serverSocket, SD_BOTH);
    closesocket(m_serverSocket);

    // Join server thread
    if (m_serverThread.joinable()) {
        m_serverThread.join();
    }

    // Join all client threads
    for (auto& thread : m_clientThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_clientThreads.clear();
}

void GDBServer::serverThread() {
    while (m_running) {
        // Accept client connection
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(m_serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            if (m_running) {
                std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
            }
            continue;
        }

        // Notify client connected
        if (m_onClientConnected) {
            m_onClientConnected(clientSocket);
        }

        // Start client thread
        m_clientThreads.emplace_back(&GDBServer::clientThread, this, clientSocket);
    }
}

void GDBServer::clientThread(SOCKET clientSocket) {
    char buffer[4096];
    std::string packet;

    // Send initial response
    std::string initResponse = "+$qSupported:multiprocess+;swbreak+;hwbreak+;qRelocInsn+;fork-events+;vfork-events+;exec-events+;vContSupported+;QThreadEvents+;no-resumed+;memory-tagging+#ec";
    size_t initResponse_size = initResponse.size();
    if (initResponse_size > INT_MAX) {
        std::cerr << "Initial response size too large for send: " << initResponse_size << std::endl;
        closesocket(clientSocket);
        return;
    }
    send(clientSocket, initResponse.c_str(), static_cast<int>(initResponse_size), 0);

    while (m_running) {
        size_t buffer_size = sizeof(buffer);
        if (buffer_size > INT_MAX) {
            std::cerr << "Buffer size too large for recv: " << buffer_size << std::endl;
            closesocket(clientSocket);
            return;
        }
        int bytesReceived = recv(clientSocket, buffer, static_cast<int>(buffer_size), 0);
        if (bytesReceived <= 0) {
            break;
        }

        // Process received data
        std::string receivedData(buffer, bytesReceived);
        if (m_onDataReceived) {
            m_onDataReceived(clientSocket, receivedData);
        }

        // Process GDB commands
        std::string response = processGDBCommand(receivedData);
        if (!response.empty()) {
            size_t response_size = response.size();
            if (response_size > INT_MAX) {
                std::cerr << "Response size too large for send: " << response_size << std::endl;
                closesocket(clientSocket);
                return;
            }
            send(clientSocket, response.c_str(), static_cast<int>(response_size), 0);
        }
    }

    // Notify client disconnected
    if (m_onClientDisconnected) {
        m_onClientDisconnected(clientSocket);
    }

    closesocket(clientSocket);
}

// Add to gdb_server.cpp
std::string GDBServer::processGDBCommand(const std::string& command) {
    if (command.empty()) return "";

    // Handle breakpoint setting (Z1 for hardware breakpoint)
    if (command[0] == 'Z' && command[1] == '1') {
        // Parse Z1,addr,len (e.g., Z1,8001bd0,2#d4)
        uint32_t address = std::stoul(command.substr(3, command.find(',') - 3), nullptr, 16);
        int result = m_stlink.debug_set_breakpoint(address, true); // Use public debug method
        return result == 0 ? "OK" : "E01";
    }
    // Handle breakpoint removal (z1 for hardware breakpoint)
    else if (command[0] == 'z' && command[1] == '1') {
        // Parse z1,addr,len (e.g., z1,8001bd0,2#f4)
        uint32_t address = std::stoul(command.substr(3, command.find(',') - 3), nullptr, 16);
        int result = m_stlink.debug_remove_breakpoint(address, true); // Use public debug method
        return result == 0 ? "OK" : "E01";
    }
    // Handle single-step
    else if (command[0] == 's') {
        // Single-step
        int result = m_stlink.debug_step(); // Use public debug method
        return result == 0 ? "T05" : "E01";
    }
    // Handle read all registers
    else if (command[0] == 'g') {
        // Read all registers
        uint32_t registers[17];
        int result = m_stlink.debug_read_registers(registers, 17); // Use public debug method
        if (result != 0) {
            return "E01";
        }
        std::string response;
        for (size_t i = 0; i < 17; i++) {
            char buf[9];
            snprintf(buf, sizeof(buf), "%08x", registers[i]);
            response += buf;
        }
        return response;
    }

    // Extract command type
    size_t dollar = command.find('$');
    size_t hash = command.find('#');
    if (dollar == std::string::npos || hash == std::string::npos) return "";

    std::string cmd = command.substr(dollar + 1, hash - dollar - 1);

    if (cmd == "qSupported") {
        return "+$PacketSize=4000;qXfer:memory-map:read+;qXfer:features:read+;QStartNoAckMode+;QNonStop+;qXfer:threads:read+;hwbreak+;swbreak+#f3";
    }
    else if (cmd == "vCont?") {
        return "+$vCont;c;s;t#05";
    }
    else if (cmd == "QStartNoAckMode") {
        return "+$OK#9a";
    }
    else if (cmd == "Hg0") {
        return "+$#00";
    }
    else if (cmd.find("qXfer:features:read:target.xml") == 0) {
        // Return target description XML
        std::string xml = R"(<?xml version="1.0"?><!DOCTYPE target SYSTEM "gdb-target.dtd"><target>
            <feature name="org.gnu.gdb.arm.m-profile">
                <reg name="r0" bitsize="32" type="uint32" regnum="0"/>
                <reg name="r1" bitsize="32" type="uint32" regnum="1"/>
                <!-- More registers... -->
            </feature>
        </target>)";
        return "+$l" + xml + "#e2";
    }
    else if (cmd.find("qXfer:threads:read") == 0) {
        return "+$l<?xml version=\"1.0\"?><threads><thread id=\"1\" core=\"0\" name=\"main\"></thread></threads>#f7";
    }
    else if (cmd.find("qXfer:memory-map:read") == 0) {
        return "+$l<?xml version=\"1.0\"?><memory-map><memory type=\"ram\" start=\"0x0\" length=\"0x8000000\"/></memory-map>#a9";
    }
    else if (cmd[0] == 'm') { // Memory read
        size_t comma = cmd.find(',');
        if (comma == std::string::npos) return "+$E01#a6";

        try {
            uint32_t addr = std::stoul(cmd.substr(1, comma - 1), nullptr, 16);
            uint32_t length = std::stoul(cmd.substr(comma + 1), nullptr, 16);

            std::vector<uint8_t> data(length);
            if (m_stlink.debug_read_memory(addr, data.data(), length) != 0) {
                return "+$E01#a6";
            }

            // Convert to hex string
            std::stringstream ss;
            for (uint8_t byte : data) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }

            return "+$" + ss.str() + "#" + checksum(ss.str());
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd[0] == 'M') { // Memory write
        size_t comma = cmd.find(',');
        size_t colon = cmd.find(':');
        if (comma == std::string::npos || colon == std::string::npos) return "+$E01#a6";

        try {
            uint32_t addr = std::stoul(cmd.substr(1, comma - 1), nullptr, 16);
            uint32_t length = std::stoul(cmd.substr(comma + 1, colon - comma - 1), nullptr, 16);
            std::string data_hex = cmd.substr(colon + 1);

            // Convert hex to binary
            std::vector<uint8_t> data;
            for (size_t i = 0; i < data_hex.size(); i += 2) {
                std::string byte_str = data_hex.substr(i, 2);
                data.push_back(static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16)));
            }

            size_t data_size = data.size();
            if (data_size > UINT32_MAX) {
                return "+$E01#a6"; // Error: data size too large
            }
            if (m_stlink.debug_write_memory(addr, data.data(), static_cast<uint32_t>(data_size)) != 0) {
                return "+$E01#a6";
            }

            return "+$OK#9a";
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd[0] == 'Z') { // Set breakpoint/watchpoint
        std::vector<std::string> parts = split(cmd.substr(1), ',');
        if (parts.size() < 3) return "+$E01#a6";

        try {
            std::string type = parts[0];
            uint32_t addr = std::stoul(parts[1], nullptr, 16);
            int kind = std::stoi(parts[2]);

            bool is_hw = (type == "1" || type == "2" || type == "3" || type == "4");
            if (m_stlink.debug_set_breakpoint(addr, is_hw) != 0) {
                return "+$E01#a6";
            }

            return "+$OK#9a";
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd[0] == 'z') { // Remove breakpoint/watchpoint
        std::vector<std::string> parts = split(cmd.substr(1), ',');
        if (parts.size() < 3) return "+$E01#a6";

        try {
            std::string type = parts[0];
            uint32_t addr = std::stoul(parts[1], nullptr, 16);
            int kind = std::stoi(parts[2]);

            bool is_hw = (type == "1" || type == "2" || type == "3" || type == "4");
            if (m_stlink.debug_remove_breakpoint(addr, is_hw) != 0) {
                return "+$E01#a6";
            }

            return "+$OK#9a";
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd[0] == 'g') { // Read all registers
        uint32_t regs[16];
        if (m_stlink.debug_read_registers(regs, 16) != 0) {
            return "+$E01#a6";
        }

        std::stringstream ss;
        for (int i = 0; i < 16; i++) {
            ss << std::hex << std::setw(8) << std::setfill('0') << regs[i];
        }

        return "+$" + ss.str() + "#" + checksum(ss.str());
    }
    else if (cmd[0] == 'p') { // Read single register
        try {
            uint8_t reg_num = static_cast<uint8_t>(std::stoul(cmd.substr(1), nullptr, 16));
            uint32_t value;

            if (m_stlink.debug_read_register(reg_num, &value) != 0) {
                return "+$E01#a6";
            }

            std::stringstream ss;
            ss << std::hex << std::setw(8) << std::setfill('0') << value;

            return "+$" + ss.str() + "#" + checksum(ss.str());
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd[0] == 'P') { // Write single register
        size_t equal = cmd.find('=');
        if (equal == std::string::npos) return "+$E01#a6";

        try {
            uint8_t reg_num = static_cast<uint8_t>(std::stoul(cmd.substr(1, equal - 1), nullptr, 16));
            uint32_t value = std::stoul(cmd.substr(equal + 1), nullptr, 16);

            if (m_stlink.debug_write_register(reg_num, value) != 0) {
                return "+$E01#a6";
            }

            return "+$OK#9a";
        }
        catch (...) {
            return "+$E01#a6";
        }
    }
    else if (cmd == "s") { // Single step
        if (m_stlink.debug_step() != 0) {
            return "+$E01#a6";
        }
        return "+$T05#b9"; // Signal TRAP
    }
    else if (cmd == "c") { // Continue
        if (m_stlink.debug_continue() != 0) {
            return "+$E01#a6";
        }
        return "+$OK#9a";
    }

    // Default response for unrecognized commands
    return "+$#00";
}