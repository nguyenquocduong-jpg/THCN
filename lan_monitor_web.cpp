// lan_monitor_web.cpp
// He thong giam sat va phan tich luu luong mang LAN o muc goi tin (Packet-level)
// Su dung thu vien WinDivert va C++.

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <iomanip>
#include <ctime>
#include <cstdlib>
#include <cstdio>
#include <chrono>
#include <cstring>
#include <algorithm>

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "windivert.h"

// Undefine MinGW macros tu windivert.h de tranh xung dot
#ifdef __out
#undef __out
#endif
#ifdef __in
#undef __in
#endif
#ifdef __inout
#undef __inout
#endif
#ifdef __out_opt
#undef __out_opt
#endif
#ifdef __in_opt
#undef __in_opt
#endif
#ifdef __inout_opt
#undef __inout_opt
#endif

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

using namespace std;

// ============================================================
// CAU TRUC DU LIEU
// ============================================================

struct Packet {
    string time;
    string protocol;
    string src;
    string dst;
    string sport;
    string dport;
    unsigned long length = 0;
};

struct Adapter {
    int index = 0;              // 1-based index cho web UI
    UINT ifIndex = 0;           // Windows Interface Index (IfIdx)
    UINT ipv6IfIndex = 0;       // Windows IPv6 Interface Index
    UINT subIfIndex = 0;        // Windows Sub-Interface Index (SubIfIdx)
    string device;              // GUID adapter
    string name;                // Ten than thien + mo ta phan cung
    bool loopback = false;
    bool connected = true;      // Trang thai cam cap mang
};

// ============================================================
// BIEN TOAN CUC VA QUAN LY LUONG
// ============================================================

mutex dataMutex;
mutex lifecycleMutex;
mutex handleMutex;

vector<Packet> packets;
map<string, unsigned long long> protocols;

atomic<bool> capturing(false);
atomic<bool> stopCapture(false);

unsigned long long totalPackets = 0;
unsigned long long totalBytes = 0;
unsigned long long pps = 0;
unsigned long long bps = 0;

thread captureThread;
HANDLE wdHandle = INVALID_HANDLE_VALUE;
string captureError;

// Bang anh xa IfIdx -> Ten card mang
unordered_map<UINT, string> g_ifIndexToName;

// ============================================================
// CAC HAM TIEN ICH
// ============================================================

string escapeJson(const string& s) {
    string out;
    out.reserve(s.size() + 8);

    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c >= 32) {
                    out += static_cast<char>(c);
                }
                break;
        }
    }
    return out;
}

string getTime() {
    time_t t = time(nullptr);
    tm local{};
    localtime_s(&local, &t);

    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", local.tm_hour, local.tm_min, local.tm_sec);
    return string(buf);
}

string ip4str(const UINT8* p) {
    char b[32];
    snprintf(b, sizeof(b), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    return b;
}

string ip6str(const UINT8* p) {
    char b[64];
    unsigned short groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = (static_cast<unsigned short>(p[i * 2]) << 8) | p[i * 2 + 1];
    }

    int bestStart = -1, bestLen = 1;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && groups[j] == 0) ++j;
        if (j - i > bestLen) {
            bestStart = i;
            bestLen = j - i;
        }
        i = j;
    }

    if (bestStart == -1) {
        snprintf(b, sizeof(b), "%x:%x:%x:%x:%x:%x:%x:%x",
                 groups[0], groups[1], groups[2], groups[3],
                 groups[4], groups[5], groups[6], groups[7]);
        return b;
    }

    string res;
    for (int i = 0; i < bestStart; ++i) {
        if (!res.empty()) res += ':';
        char seg[8];
        snprintf(seg, sizeof(seg), "%x", groups[i]);
        res += seg;
    }
    res += "::";
    for (int i = bestStart + bestLen; i < 8; ++i) {
        if (i > bestStart + bestLen) res += ':';
        char seg[8];
        snprintf(seg, sizeof(seg), "%x", groups[i]);
        res += seg;
    }
    return res;
}

string protocolName(unsigned int p) {
    switch (p) {
        case 1:  return "ICMP";
        case 2:  return "IGMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        default: return "Other";
    }
}

string lowerAscii(string value) {
    for (char& c : value) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return value;
}

string wideToUtf8(const wchar_t* value) {
    if (!value || !*value) return "";
    int needed = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 1) return "";
    string result(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, result.data(), needed, nullptr, nullptr);
    if (!result.empty() && result.back() == '\0') {
        result.pop_back();
    }
    return result;
}

// ============================================================
// PHAN TICH GOI TIN NETWORK LAYER (WINDIVERT)
// ============================================================

void storePacket(const Packet& p) {
    lock_guard<mutex> lock(dataMutex);

    packets.push_back(p);

    if (packets.size() > 3000) {
        packets.erase(packets.begin(), packets.begin() + 1000);
    }

    ++totalPackets;
    totalBytes += p.length;
    ++protocols[p.protocol];
}

void analyzePacket(const UINT8* data, UINT len) {
    if (!data || len < 20) {
        return;
    }

    UINT8 version = (data[0] >> 4) & 0x0F;

    // Chi xu ly goi tin IPv4 de dam bao 100% dia chi IP dang so thuan tuy (khong bi lan chu cai / ky tu la cua IPv6)
    if (version != 4) {
        return;
    }

    Packet p{};
    p.time = getTime();
    p.protocol = "Other";
    p.src = "-";
    p.dst = "-";
    p.sport = "-";
    p.dport = "-";
    p.length = len;

    UINT ihl = (data[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl) {
        return;
    }

    p.src = ip4str(data + 12);
    p.dst = ip4str(data + 16);

    UINT8 proto = data[9];
    p.protocol = protocolName(proto);

    UINT frag = (static_cast<UINT>(data[6]) << 8) | static_cast<UINT>(data[7]);
    bool firstFragment = ((frag & 0x1FFF) == 0);

    if ((proto == 6 || proto == 17) && firstFragment && len >= ihl + 4) {
        UINT sport = (static_cast<UINT>(data[ihl]) << 8) | data[ihl + 1];
        UINT dport = (static_cast<UINT>(data[ihl + 2]) << 8) | data[ihl + 3];
        p.sport = to_string(sport);
        p.dport = to_string(dport);
    }

    storePacket(p);
}

// ============================================================
// ANH XA ADAPTER VA IP HELPER API
// ============================================================

vector<Adapter> getAdapters() {
    vector<Adapter> result;

    ULONG bufferSize = 32 * 1024;
    vector<BYTE> buffer(bufferSize);

    ULONG ret = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
        &bufferSize
    );

    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(bufferSize);
        ret = GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data()),
            &bufferSize
        );
    }

    if (ret != NO_ERROR) {
        char msg[128];
        snprintf(msg, sizeof(msg), "GetAdaptersAddresses loi: %lu", ret);
        lock_guard<mutex> lock(dataMutex);
        captureError = msg;
        return result;
    }

    unordered_map<UINT, string> newIfMap;
    int index = 0;

    auto* adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.data());
    for (; adapter; adapter = adapter->Next) {
        if (!adapter->AdapterName) continue;

        // Bỏ qua các adapter tunnel ảo
        if (adapter->IfType == IF_TYPE_TUNNEL) {
            continue;
        }

        Adapter a;
        a.index = ++index;
        a.ifIndex = adapter->IfIndex;
        a.ipv6IfIndex = adapter->Ipv6IfIndex;
        a.subIfIndex = 0;
        a.device = adapter->AdapterName;
        a.loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        a.connected = (adapter->OperStatus == IfOperStatusUp || a.loopback);

        string friendly = wideToUtf8(adapter->FriendlyName);
        string description = wideToUtf8(adapter->Description);

        if (!friendly.empty() && !description.empty() &&
            lowerAscii(friendly) != lowerAscii(description)) {
            a.name = friendly + " — " + description;
        } else if (!friendly.empty()) {
            a.name = friendly;
        } else if (!description.empty()) {
            a.name = description;
        } else {
            a.name = a.device;
        }

        if (a.loopback && a.name.find("Loopback") == string::npos) {
            a.name += " (Loopback)";
        } else if (!a.loopback && adapter->OperStatus == IfOperStatusDown) {
            a.name += " (Chưa cắm cáp)";
        }

        // Anh xa IfIdx va Ipv6IfIndex sang ten card mang
        if (a.ifIndex != 0) newIfMap[a.ifIndex] = a.name;
        if (a.ipv6IfIndex != 0) newIfMap[a.ipv6IfIndex] = a.name;

        result.push_back(a);
    }

    {
        lock_guard<mutex> lock(dataMutex);
        g_ifIndexToName = std::move(newIfMap);
    }

    return result;
}

// ============================================================
// VONG LAP BAT GOI TIN (WINDIVERT CAPTURE LOOP)
// ============================================================

void captureLoop(Adapter selected) {
    char filter[256];

    // Bat goi tin IPv4 thuan tuy (khong bat IPv6 de dam bao 100% dia chi IP dang so thuan LAN)
    if (selected.loopback) {
        snprintf(filter, sizeof(filter), "ip and (loopback or (ifIdx == %u))", selected.ifIndex);
    } else {
        snprintf(filter, sizeof(filter), "ip and (ifIdx == %u)", selected.ifIndex);
    }

    // Mo WinDivert o Network Layer che do SNIFF (quan sat, khong can thiep / block goi)
    HANDLE hWD = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);

    if (hWD == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        char msg[256];
        if (err == 5) {
            snprintf(msg, sizeof(msg),
                     "Loi 5 (Access Denied): WinDivert yeu cau chay bang quyen Administrator (Run as administrator).");
        } else if (err == 2 || err == 3) {
            snprintf(msg, sizeof(msg),
                     "Khong tim thay file WinDivert64.sys hoac WinDivert.dll (Loi %lu).", err);
        } else {
            snprintf(msg, sizeof(msg),
                     "WinDivertOpen that bai. Ma loi Windows: %lu. Hay chay quyen Administrator.", err);
        }

        {
            lock_guard<mutex> lock(dataMutex);
            captureError = msg;
        }
        capturing = false;
        return;
    }

    {
        lock_guard<mutex> lock(handleMutex);
        wdHandle = hWD;
    }

    const UINT BUFSIZE = 65535;
    vector<UINT8> buf(BUFSIZE);

    unsigned long long lastPackets = 0;
    unsigned long long lastBytes = 0;
    auto last = chrono::steady_clock::now();

    while (!stopCapture.load()) {
        WINDIVERT_ADDRESS addr{};
        UINT recvLen = 0;

        BOOL ok = WinDivertRecv(hWD, buf.data(), BUFSIZE, &recvLen, &addr);

        if (!ok) {
            DWORD err = GetLastError();

            // Dung chu dong qua WinDivertShutdown hoac close
            if (stopCapture.load() || err == ERROR_OPERATION_ABORTED || err == ERROR_INVALID_HANDLE) {
                break;
            }

            char msg[128];
            snprintf(msg, sizeof(msg), "WinDivertRecv loi: %lu", err);
            lock_guard<mutex> lock(dataMutex);
            captureError = msg;
            break;
        }

        if (recvLen > 0) {
            // Kiem tra bo loc interface bo sung de dam bao chinh xac
            if (selected.loopback ||
                addr.Network.IfIdx == selected.ifIndex ||
                (selected.ipv6IfIndex != 0 && addr.Network.IfIdx == selected.ipv6IfIndex)) {
                analyzePacket(buf.data(), recvLen);
            }
        }

        auto now = chrono::steady_clock::now();
        auto elapsed = chrono::duration_cast<chrono::milliseconds>(now - last).count();

        if (elapsed >= 1000) {
            lock_guard<mutex> lock(dataMutex);

            unsigned long long packetDelta = totalPackets - lastPackets;
            unsigned long long byteDelta = totalBytes - lastBytes;

            pps = packetDelta * 1000 / static_cast<unsigned long long>(elapsed);
            bps = byteDelta * 8 * 1000 / static_cast<unsigned long long>(elapsed);

            lastPackets = totalPackets;
            lastBytes = totalBytes;
            last = now;
        }
    }

    {
        lock_guard<mutex> lock(handleMutex);
        if (wdHandle == hWD) {
            wdHandle = INVALID_HANDLE_VALUE;
            WinDivertClose(hWD);
        }
    }

    capturing = false;
}

// ============================================================
// KHOI DONG / DUNG CAPTURE AN TOAN
// ============================================================

bool startCapture(int selectedIndex) {
    lock_guard<mutex> lifecycleLock(lifecycleMutex);

    // Neu dang chay ma nguoi dung bam Start (doi card mang hoac khoi dong lai), dung capture cu an toan
    if (capturing.load()) {
        stopCapture = true;
        {
            lock_guard<mutex> lock(handleMutex);
            if (wdHandle != INVALID_HANDLE_VALUE) {
                WinDivertShutdown(wdHandle, WINDIVERT_SHUTDOWN_RECV);
            }
        }
        if (captureThread.joinable()) {
            captureThread.join();
        }
        {
            lock_guard<mutex> lock(handleMutex);
            if (wdHandle != INVALID_HANDLE_VALUE) {
                WinDivertClose(wdHandle);
                wdHandle = INVALID_HANDLE_VALUE;
            }
        }
        capturing = false;
    }

    if (captureThread.joinable()) {
        captureThread.join();
    }

    auto adapters = getAdapters();
    Adapter selected;
    bool found = false;

    for (const auto& a : adapters) {
        if (a.index == selectedIndex) {
            selected = a;
            found = true;
            break;
        }
    }

    if (!found) {
        return false;
    }

    if (!selected.connected && !selected.loopback) {
        lock_guard<mutex> lock(dataMutex);
        captureError = "Card mang nay chua cam cap mang LAN (Disconnected). Vui long cam cap hoac chon card Wi-Fi.";
        return false;
    }

    {
        lock_guard<mutex> lock(dataMutex);
        packets.clear();
        protocols.clear();
        totalPackets = 0;
        totalBytes = 0;
        pps = 0;
        bps = 0;
        captureError.clear();
    }

    stopCapture = false;
    capturing = true;

    captureThread = thread(captureLoop, selected);
    return true;
}

void stopCaptureThread() {
    lock_guard<mutex> lifecycleLock(lifecycleMutex);

    stopCapture = true;

    {
        lock_guard<mutex> lock(handleMutex);
        if (wdHandle != INVALID_HANDLE_VALUE) {
            WinDivertShutdown(wdHandle, WINDIVERT_SHUTDOWN_RECV);
        }
    }

    if (captureThread.joinable()) {
        captureThread.join();
    }

    {
        lock_guard<mutex> lock(handleMutex);
        if (wdHandle != INVALID_HANDLE_VALUE) {
            WinDivertClose(wdHandle);
            wdHandle = INVALID_HANDLE_VALUE;
        }
    }

    capturing = false;
}

// ============================================================
// DOC TAI NGUYEN HTML
// ============================================================

string readHtml() {
    ifstream file("index.html", ios::binary);
    if (!file) {
        return "<!doctype html><html><body>"
               "<h2>Khong tim thay index.html</h2>"
               "<p>Dat index.html cung thu muc voi file exe.</p>"
               "</body></html>";
    }

    stringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// ============================================================
// DINH DANG DU LIEU JSON CHO FRONTEND
// ============================================================

string adaptersJson() {
    auto adapters = getAdapters();

    stringstream ss;
    ss << "{\"adapters\":[";

    for (size_t i = 0; i < adapters.size(); ++i) {
        if (i) ss << ",";
        const auto& a = adapters[i];
        ss << "{"
           << "\"index\":" << a.index
           << ",\"name\":\"" << escapeJson(a.name) << "\""
           << ",\"device\":\"" << escapeJson(a.device) << "\""
           << ",\"loopback\":" << (a.loopback ? "true" : "false")
           << ",\"connected\":" << (a.connected ? "true" : "false")
           << "}";
    }

    ss << "]}";
    return ss.str();
}

string statusJson() {
    lock_guard<mutex> lock(dataMutex);

    stringstream ss;
    ss << "{"
       << "\"capturing\":" << (capturing ? "true" : "false")
       << ",\"totalPackets\":" << totalPackets
       << ",\"totalBytes\":" << totalBytes
       << ",\"pps\":" << pps
       << ",\"bps\":" << bps
       << ",\"error\":\"" << escapeJson(captureError) << "\""
       << ",\"protocols\":{";

    bool first = true;
    for (const auto& item : protocols) {
        if (!first) ss << ",";
        first = false;
        ss << "\"" << escapeJson(item.first) << "\":" << item.second;
    }

    ss << "}}";
    return ss.str();
}

string packetsJson() {
    lock_guard<mutex> lock(dataMutex);

    stringstream ss;
    ss << "{\"packets\":[";

    size_t start = packets.size() > 100 ? packets.size() - 100 : 0;
    for (size_t i = start; i < packets.size(); ++i) {
        if (i > start) ss << ",";
        const auto& p = packets[i];
        ss << "{"
           << "\"time\":\"" << escapeJson(p.time) << "\""
           << ",\"protocol\":\"" << escapeJson(p.protocol) << "\""
           << ",\"src\":\"" << escapeJson(p.src) << "\""
           << ",\"dst\":\"" << escapeJson(p.dst) << "\""
           << ",\"sport\":\"" << escapeJson(p.sport) << "\""
           << ",\"dport\":\"" << escapeJson(p.dport) << "\""
           << ",\"length\":" << p.length
           << "}";
    }

    ss << "]}";
    return ss.str();
}

// ============================================================
// MAY CHU HTTP
// ============================================================

void response(
    SOCKET client,
    const string& contentType,
    const string& body,
    const string& status = "200 OK"
) {
    stringstream ss;
    ss << "HTTP/1.1 " << status << "\r\n"
       << "Content-Type: " << contentType << "\r\n"
       << "Cache-Control: no-store\r\n"
       << "Connection: close\r\n"
       << "Content-Length: " << body.size()
       << "\r\n\r\n"
       << body;

    string result = ss.str();
    size_t sent = 0;

    while (sent < result.size()) {
        int n = send(
            client,
            result.data() + sent,
            static_cast<int>(result.size() - sent),
            0
        );
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }
}

string requestBody(const string& req) {
    size_t p = req.find("\r\n\r\n");
    if (p == string::npos) return "";
    return req.substr(p + 4);
}

int bodyIndex(const string& body) {
    size_t p = body.find("\"index\"");
    if (p == string::npos) return 0;
    p = body.find(':', p);
    if (p == string::npos) return 0;
    return atoi(body.c_str() + p + 1);
}

void handleClient(SOCKET client) {
    string req;
    char buffer[4096];
    size_t headerEnd = string::npos;

    while (req.size() < 65536 && headerEnd == string::npos) {
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n <= 0) return;
        req.append(buffer, n);
        headerEnd = req.find("\r\n\r\n");
    }

    if (headerEnd == string::npos) {
        response(client, "application/json", "{\"error\":\"Bad request\"}", "400 Bad Request");
        return;
    }

    size_t contentLength = 0;
    size_t cl = req.find("Content-Length:");
    if (cl != string::npos && cl < headerEnd) {
        cl += strlen("Content-Length:");
        while (cl < headerEnd && req[cl] == ' ') ++cl;
        contentLength = static_cast<size_t>(strtoul(req.c_str() + cl, nullptr, 10));
    }

    size_t bodyStart = headerEnd + 4;
    while (req.size() - bodyStart < contentLength && req.size() < 65536 + contentLength) {
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n <= 0) break;
        req.append(buffer, n);
    }

    string firstLine = req.substr(0, req.find("\r\n"));
    string body = requestBody(req);

    // GET /api/adapters
    if (firstLine.find("GET /api/adapters ") == 0) {
        response(client, "application/json; charset=utf-8", adaptersJson());
    }
    // GET /api/status
    else if (firstLine.find("GET /api/status ") == 0) {
        response(client, "application/json; charset=utf-8", statusJson());
    }
    // GET /api/packets
    else if (firstLine.find("GET /api/packets ") == 0) {
        response(client, "application/json; charset=utf-8", packetsJson());
    }
    // GET / hoac GET /index.html
    else if (firstLine.find("GET / ") == 0 || firstLine.find("GET /index.html ") == 0) {
        response(client, "text/html; charset=utf-8", readHtml());
    }
    // POST /api/start
    else if (firstLine.find("POST /api/start ") == 0) {
        int idx = bodyIndex(body);
        if (idx <= 0) {
            response(client, "application/json", "{\"error\":\"Adapter khong hop le\"}", "400 Bad Request");
            return;
        }

        if (!startCapture(idx)) {
            response(client, "application/json",
                     "{\"error\":\"Khong the bat dau capture. Kiem tra adapter hoac trang thai capture.\"}",
                     "409 Conflict");
            return;
        }

        response(client, "application/json", "{\"ok\":true}");
    }
    // POST /api/stop
    else if (firstLine.find("POST /api/stop ") == 0) {
        stopCaptureThread();
        response(client, "application/json", "{\"ok\":true}");
    }
    // POST /api/reset (Xoa sach toan bo thong ke va goi tin ve 0)
    else if (firstLine.find("POST /api/reset ") == 0) {
        {
            lock_guard<mutex> lock(dataMutex);
            packets.clear();
            protocols.clear();
            totalPackets = 0;
            totalBytes = 0;
            pps = 0;
            bps = 0;
            captureError.clear();
        }
        response(client, "application/json", "{\"ok\":true}");
    }
    // 404 Not Found
    else {
        response(client, "application/json", "{\"error\":\"Not found\"}", "404 Not Found");
    }
}

// ============================================================
// HAM MAIN
// ============================================================

int main() {
    // Kiem tra thu vien WinDivert.dll
    HMODULE hDll = LoadLibraryA("WinDivert.dll");
    if (!hDll) {
        DWORD err = GetLastError();
        cerr << "[LOI] Khong the nap WinDivert.dll (Loi Windows: " << err << ")\n";
        cerr << "[HUONG DAN] Hay dat WinDivert.dll va WinDivert64.sys cung thu muc voi lan_monitor_web.exe\n";
        return 1;
    }
    FreeLibrary(hDll);

    // Khoi tao Windows Sockets
    WSADATA wsa{};
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsa);
    if (wsaResult != 0) {
        cerr << "WSAStartup failed: " << wsaResult << "\n";
        return 1;
    }

    SOCKET server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server == INVALID_SOCKET) {
        cerr << "Khong tao duoc socket: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }

    int optVal = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&optVal), sizeof(optVal));

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(8080);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(server, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        cerr << "[LOI] Khong mo duoc cong 8080. Co the cong dang duoc chuong trinh khac su dung.\n";
        closesocket(server);
        WSACleanup();
        return 1;
    }

    if (listen(server, 64) == SOCKET_ERROR) {
        cerr << "Listen failed: " << WSAGetLastError() << "\n";
        closesocket(server);
        WSACleanup();
        return 1;
    }

    cout << "========================================================\n";
    cout << "  LAN MONITOR WEB - WINDIVERT EDITION                   \n";
    cout << "  He thong giam sat va phan tich luu luong mang LAN     \n";
    cout << "========================================================\n";
    cout << "  Web UI dang chay tai: http://127.0.0.1:8080           \n";
    cout << "  Luon chay chuong trinh bang quyen 'Run as administrator'\n";
    cout << "  Nhan Ctrl+C tren cua so nay de dung may chu.          \n";
    cout << "========================================================\n" << flush;

    while (true) {
        SOCKET client = accept(server, nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            break;
        }

        // Xu ly client HTTP tren thread rieng
        thread([client]() {
            DWORD timeout = 5000;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
            setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

            handleClient(client);
            closesocket(client);
        }).detach();
    }

    stopCaptureThread();
    closesocket(server);
    WSACleanup();

    return 0;
}
