#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include "stlink_server.h"
using std::string;
using std::vector;

class GDBServer {
public:
    GDBServer(int port = 61234);
    ~GDBServer();

    bool start();
    void stop();
    bool isRunning() const { return m_running; }

    void setOnClientConnected(std::function<void(SOCKET)> callback) { m_onClientConnected = callback; }
    void setOnClientDisconnected(std::function<void(SOCKET)> callback) { m_onClientDisconnected = callback; }
    void setOnDataReceived(std::function<void(SOCKET, const std::string&)> callback) { m_onDataReceived = callback; }

private:
    void serverThread();
    void clientThread(SOCKET clientSocket);
    std::string processGDBCommand(const std::string& command);
    STLinkServer m_stlink;

    int m_port;
    SOCKET m_serverSocket;
    std::atomic<bool> m_running;
    std::thread m_serverThread;
    std::vector<std::thread> m_clientThreads;

    std::function<void(SOCKET)> m_onClientConnected;
    std::function<void(SOCKET)> m_onClientDisconnected;
    std::function<void(SOCKET, const std::string&)> m_onDataReceived;
};