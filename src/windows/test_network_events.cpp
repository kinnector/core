#include "etw_consumer.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <chrono>
#include <string>
#include <thread>

#pragma comment(lib, "ws2_32")

using kinnector::windows::EtwConsumer;

namespace {

std::mutex g_mutex;
std::condition_variable g_cv;
std::vector<TelemetryEvent> g_events;
DWORD g_self_pid = 0;

void OnEvent(const TelemetryEvent& event) {
    if (event.header.pid != g_self_pid) return;
    std::lock_guard<std::mutex> lock(g_mutex);
    g_events.push_back(event);
    g_cv.notify_all();
}

template <typename Pred>
bool WaitForEvent(EventType type, Pred pred, TelemetryEvent* out, int timeout_ms) {
    std::unique_lock<std::mutex> lock(g_mutex);
    return g_cv.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
        for (const auto& ev : g_events) {
            if (ev.header.event_type == type && pred(ev)) {
                *out = ev;
                return true;
            }
        }
        return false;
    });
}

bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool ok = GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated;
}

} // namespace

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "[Test] CHECK FAILED: " << msg << " (" << #cond << ")" << std::endl; \
            consumer.Stop(); \
            WSACleanup(); \
            return 1; \
        } \
    } while (0)

static constexpr int kSkipReturnCode = 127;

int main() {
    std::cout << "=== Running Windows Network Events (connect/accept/UDP) Test ===" << std::endl;

    if (!IsElevated()) {
        std::cout << "[Test] SKIPPED: not running elevated (Administrator) - "
                     "real Kernel-Network ETW tracing requires it. "
                     "Re-run this test from an elevated session to actually validate it."
                  << std::endl;
        return kSkipReturnCode;
    }

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[Test] WSAStartup failed" << std::endl;
        return 1;
    }
    g_self_pid = GetCurrentProcessId();

    EtwConsumer consumer;
    if (!consumer.Initialize()) {
        std::cerr << "[Test] EtwConsumer::Initialize failed even though elevated" << std::endl;
        return 1;
    }
    consumer.SetEventCallback(OnEvent);
    if (!consumer.Start()) {
        std::cerr << "[Test] EtwConsumer::Start failed" << std::endl;
        return 1;
    }

    const uint16_t kListenPort = 58311;
    const uint16_t kUdpPort = 58312;

    std::cout << "[Test] TCP listen..." << std::endl;
    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(listen_sock != INVALID_SOCKET, "listen socket created");
    sockaddr_in listen_addr = {};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    listen_addr.sin_port = htons(kListenPort);
    CHECK(bind(listen_sock, reinterpret_cast<sockaddr*>(&listen_addr), sizeof(listen_addr)) == 0,
          "bind succeeded");
    CHECK(listen(listen_sock, 1) == 0, "listen succeeded");

    std::thread acceptor([&]() {
        sockaddr_in peer{};
        int peer_len = sizeof(peer);
        SOCKET s = accept(listen_sock, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (s != INVALID_SOCKET) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            closesocket(s);
        }
    });

    std::cout << "[Test] TCP connect..." << std::endl;
    SOCKET client_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(client_sock != INVALID_SOCKET, "client socket created");
    sockaddr_in connect_addr = {};
    connect_addr.sin_family = AF_INET;
    connect_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect_addr.sin_port = htons(kListenPort);
    CHECK(connect(client_sock, reinterpret_cast<sockaddr*>(&connect_addr),
                  sizeof(connect_addr)) == 0, "connect succeeded");

    TelemetryEvent connect_ev{};
    bool got_connect = WaitForEvent(EventType::NetworkConnect, [&](const TelemetryEvent& ev) {
        return ev.details.network_connect.destination_port == kListenPort &&
               std::string(ev.details.network_connect.protocol) == "TCP";
    }, &connect_ev, 5000);
    CHECK(got_connect, "NetworkConnect (TCP) event observed for the real connect()");
    CHECK(std::string(connect_ev.details.network_connect.destination_ip) == "127.0.0.1",
          "destination_ip is 127.0.0.1");
    std::cout << "[Test] NetworkConnect: ip=" << connect_ev.details.network_connect.destination_ip
              << " port=" << connect_ev.details.network_connect.destination_port
              << " protocol=" << connect_ev.details.network_connect.protocol << std::endl;

    TelemetryEvent accept_ev{};
    bool got_accept = WaitForEvent(EventType::NetworkAccept, [&](const TelemetryEvent& ev) {
        return ev.details.network_accept.local_port == kListenPort;
    }, &accept_ev, 5000);
    CHECK(got_accept, "NetworkAccept event observed for the real accept()");
    CHECK(std::string(accept_ev.details.network_accept.remote_ip) == "127.0.0.1",
          "remote_ip is 127.0.0.1");
    std::cout << "[Test] NetworkAccept: remote_ip=" << accept_ev.details.network_accept.remote_ip
              << " remote_port=" << accept_ev.details.network_accept.remote_port
              << " local_port=" << accept_ev.details.network_accept.local_port << std::endl;

    acceptor.join();
    closesocket(client_sock);
    closesocket(listen_sock);

    std::cout << "[Test] UDP send..." << std::endl;
    SOCKET udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    CHECK(udp_sock != INVALID_SOCKET, "udp socket created");
    sockaddr_in udp_addr = {};
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    udp_addr.sin_port = htons(kUdpPort);
    const char* msg = "kinnector udp test";
    CHECK(sendto(udp_sock, msg, static_cast<int>(strlen(msg)), 0,
                 reinterpret_cast<sockaddr*>(&udp_addr), sizeof(udp_addr)) > 0,
          "sendto succeeded");

    TelemetryEvent udp_ev{};
    bool got_udp = WaitForEvent(EventType::NetworkConnect, [&](const TelemetryEvent& ev) {
        return ev.details.network_connect.destination_port == kUdpPort &&
               std::string(ev.details.network_connect.protocol) == "UDP";
    }, &udp_ev, 5000);
    CHECK(got_udp, "NetworkConnect (UDP) event observed for the real sendto()");
    std::cout << "[Test] UDP NetworkConnect: ip=" << udp_ev.details.network_connect.destination_ip
              << " port=" << udp_ev.details.network_connect.destination_port
              << " protocol=" << udp_ev.details.network_connect.protocol << std::endl;

    closesocket(udp_sock);
    consumer.Stop();
    WSACleanup();

    std::cout << "\n>>> TEST SUCCESSFUL! TCP connect/accept + UDP send telemetry validated. <<<" << std::endl;
    return 0;
}
