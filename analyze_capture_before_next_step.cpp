
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm>
#include <cctype>
#include <vector>
#include <pcap.h>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <conio.h>

using namespace std;

struct Endpoint {
    string ip;
    string port;
};

struct Statistics {
    long long count = 0;
    long long bytes = 0;
};

string trim(const string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (first == string::npos)
        return "";

    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}

string toLower(string s) {
    transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) {
            return static_cast<char>(tolower(c));
        });
    return s;
}

// Lay phan mo ta goi tin sau "ethertype ... length ...:"
string getPacketDescription(const string& line) {
    size_t ethertype = line.find("ethertype ");
    if (ethertype == string::npos)
        return "";

    size_t colon = line.find(": ", ethertype);
    if (colon == string::npos)
        return "";

    return trim(line.substr(colon + 2));
}

// Lay do dai goi tin tu "length N"
string getPacketSize(const string& line) {
    size_t pos = line.find("length ");
    if (pos == string::npos)
        return "-";

    pos += 7;
    size_t end = pos;

    while (end < line.size() &&
           isdigit(static_cast<unsigned char>(line[end]))) {
        end++;
    }

    if (end == pos)
        return "-";

    return line.substr(pos, end - pos);
}

long long parseSize(const string& s) {
    try {
        return stoll(s);
    } catch (...) {
        return 0;
    }
}

// Phan loai loai dia chi
string getAddressType(const string& line) {
    string lower = toLower(line);

    if (lower.find("ethertype ipv4") != string::npos ||
        lower.find("ethertype ip (") != string::npos) {
        return "IPv4";
    }

    if (lower.find("ethertype ipv6") != string::npos) {
        return "IPv6";
    }

    if (lower.find("ethertype arp") != string::npos) {
        return "ARP";
    }

    return "Khac";
}

// Phan loai giao thuc
string getProtocol(const string& line) {
    string lower = toLower(line);
    string description = toLower(getPacketDescription(line));

    if (lower.find("ethertype arp") != string::npos)
        return "ARP";

    if (description.find("icmp6") != string::npos ||
        description.find("icmp6,") != string::npos ||
        description.find("icmpv6") != string::npos) {
        return "ICMP";
    }

    if (description.find("icmp") != string::npos)
        return "ICMP";

    if (description.find("tcp") != string::npos ||
        description.find("flags [") != string::npos) {
        return "TCP";
    }

    if (description.find("udp") != string::npos ||
        description.find(" a? ") != string::npos ||
        description.find(" aaaa? ") != string::npos ||
        description.find(" mdns") != string::npos) {
        return "UDP";
    }

    return "Khac";
}

// Tach IP va cong tu mot dau cuoi ket noi
Endpoint parseEndpoint(const string& endpoint) {
    string value = trim(endpoint);
    Endpoint result = {"-", "-"};

    if (value.empty())
        return result;

    // Bo dau phay hoac ky tu ket thuc neu co
    while (!value.empty() &&
           (value.back() == ',' || value.back() == ';')) {
        value.pop_back();
    }

    // IPv6: dia chi co dau ':'.
    // Neu co '.port' o cuoi thi tach cong.
    if (value.find(':') != string::npos) {
        size_t dot = value.rfind('.');

        if (dot != string::npos && dot + 1 < value.size()) {
            string possiblePort = value.substr(dot + 1);

            bool isNumber = all_of(
                possiblePort.begin(), possiblePort.end(),
                [](unsigned char c) {
                    return isdigit(c);
                });

            if (isNumber) {
                result.ip = value.substr(0, dot);
                result.port = possiblePort;
                return result;
            }
        }

        // IPv6 khong co cong, thuong gap voi ICMPv6
        result.ip = value;
        return result;
    }

    // IPv4 co 3 dau cham trong dia chi.
    // Neu co them dau cham thu 4 thi phan cuoi la cong.
    size_t dotCount = count(value.begin(), value.end(), '.');

    if (dotCount >= 4) {
        size_t dot = value.rfind('.');
        string possiblePort = value.substr(dot + 1);

        bool isNumber = !possiblePort.empty() &&
            all_of(possiblePort.begin(), possiblePort.end(),
                [](unsigned char c) {
                    return isdigit(c);
                });

        if (isNumber) {
            result.ip = value.substr(0, dot);
            result.port = possiblePort;
            return result;
        }
    }

    // IPv4 khong co cong
    result.ip = value;
    return result;
}

// Lay dia chi IP nguon
Endpoint getSourceEndpoint(const string& line) {
    string description = getPacketDescription(line);
    size_t arrow = description.find(" > ");

    if (arrow == string::npos)
        return {"-", "-"};

    string source = trim(description.substr(0, arrow));
    return parseEndpoint(source);
}

// Lay dia chi IP dich
Endpoint getDestinationEndpoint(const string& line) {
    string description = getPacketDescription(line);
    size_t arrow = description.find(" > ");

    if (arrow == string::npos)
        return {"-", "-"};

    size_t start = arrow + 3;
    size_t end = string::npos;

    // Cac dau hieu ket thuc phan dia chi dich
    const string markers[] = {
        ": UDP,",
        ": TCP,",
        ": ICMP,",
        ": ICMP6,",
        ": ICMP6 ",
        ": Flags [",
        ": UDP ",
        ": TCP ",
        ": ICMP ",
        ", seq ",
        ", ack ",
        ", win ",
        ", length "
    };

    for (const string& marker : markers) {
        size_t found = description.find(marker, start);

        if (found != string::npos &&
            (end == string::npos || found < end)) {
            end = found;
        }
    }

    // Ho tro dong DNS dang:
    // 192.168.1.1.53: 7423+ A? example.com
    // Dau ": " sau dia chi dich dung lam moc ket thuc.
    if (end == string::npos) {
        size_t colonSpace = description.find(": ", start);

        if (colonSpace != string::npos)
            end = colonSpace;
    }

    if (end == string::npos)
        return {"-", "-"};

    string destination = trim(
        description.substr(start, end - start));

    return parseEndpoint(destination);
}

struct Packet {
    string addressType;
    string protocol;
    Endpoint source;
    Endpoint destination;
    string sizeText;
    long long bytes = 0;
};

string csvEscape(const string& value) {
    string out = "\"";
    for (char c : value) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

bool containsInsensitive(const string& value, const string& filter) {
    if (filter.empty() || filter == "-") return true;
    return toLower(value).find(toLower(filter)) != string::npos;
}


// Bat goi truc tiep bang Npcap.
// Ho tro Ethernet, IPv4, IPv6 co ban, ARP, TCP, UDP va ICMP.
int runLiveCapture() {
    pcap_if_t* devices = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE] = {};

    if (pcap_findalldevs(&devices, errbuf) == -1) {
        cerr << "Loi liet ke adapter: " << errbuf << '\n';
        return 1;
    }

    int count = 0;
    for (pcap_if_t* d = devices; d; d = d->next) {
        ++count;
        cout << count << ". "
             << (d->description ? d->description : d->name)
             << '\n';
    }

    if (count == 0) {
        cerr << "Khong tim thay adapter mang.\n";
        pcap_freealldevs(devices);
        return 1;
    }

    int choice = 0;
    cout << "Chon adapter (4 = Wi-Fi neu danh sach giong may thu): ";
    if (!(cin >> choice) || choice < 1 || choice > count) {
        cerr << "Lua chon khong hop le.\n";
        pcap_freealldevs(devices);
        return 1;
    }

    pcap_if_t* selected = devices;
    for (int i = 1; i < choice; ++i)
        selected = selected->next;

    if (!selected->name) {
        pcap_freealldevs(devices);
        cerr << "Adapter khong co ten.\n";
        return 1;
    }

    string deviceName = selected->name;
    pcap_freealldevs(devices);

    char openError[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_live(
        deviceName.c_str(), 65536, 1, 250, openError
    );

    if (!handle) {
        cerr << "Khong mo duoc adapter: " << openError << '\n';
        cerr << "Hay thu mo PowerShell bang Run as administrator.\n";
        return 1;
    }

    if (pcap_datalink(handle) != DLT_EN10MB) {
        cerr << "Adapter nay khong tra ve khung Ethernet. "
             << "Hay thu adapter Wi-Fi hoac Ethernet khac.\n";
        pcap_close(handle);
        return 1;
    }

    vector<Packet> packets;
    unsigned long long totalBytes = 0;
    unsigned long long totalPackets = 0;
    unsigned long long lastReportPackets = 0;
    unsigned long long lastReportBytes = 0;
    time_t lastReport = time(nullptr);

    cout << "\nDang bat goi. Nhan q de dung.\n";
    cout << "Chi giam sat luu luong tren adapter da chon.\n";

    auto ipv4Text = [](const u_char* p) -> string {
        char b[32];
        snprintf(b, sizeof(b), "%u.%u.%u.%u",
                 (unsigned)p[0], (unsigned)p[1],
                 (unsigned)p[2], (unsigned)p[3]);
        return b;
    };

    auto ipv6Text = [](const u_char* p) -> string {
        char b[64];
        snprintf(b, sizeof(b),
            "%x:%x:%x:%x:%x:%x:%x:%x",
            (p[0] << 8) | p[1], (p[2] << 8) | p[3],
            (p[4] << 8) | p[5], (p[6] << 8) | p[7],
            (p[8] << 8) | p[9], (p[10] << 8) | p[11],
            (p[12] << 8) | p[13], (p[14] << 8) | p[15]);
        return b;
    };

    bool stop = false;

    while (!stop) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 'q' || key == 'Q')
                break;
        }

        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        int result = pcap_next_ex(handle, &header, &data);

        if (result == -1) {
            cerr << "\nLoi khi bat goi: "
                 << pcap_geterr(handle) << '\n';
            break;
        }

        if (result == 1 && header && data) {
            ++totalPackets;
            totalBytes += header->caplen;

            Packet p;
            p.addressType = "Khac";
            p.protocol = "OTHER";
            p.source = {"-", "-"};
            p.destination = {"-", "-"};
            p.bytes = header->len;
            p.sizeText = to_string(header->len);

            size_t n = header->caplen;
            size_t off = 14;

            if (n >= 14) {
                unsigned int type =
                    (unsigned(data[12]) << 8) | data[13];

                // Xu ly VLAN 802.1Q va QinQ co ban.
                while ((type == 0x8100 || type == 0x88a8) &&
                       n >= off + 4) {
                    type = (unsigned(data[off + 2]) << 8)
                         | data[off + 3];
                    off += 4;
                }

                if (type == 0x0806) {
                    p.addressType = "ARP";
                    p.protocol = "ARP";
                } else if (type == 0x0800 && n >= off + 20) {
                    unsigned ihl = (data[off] & 0x0f) * 4;

                    if (ihl >= 20 && n >= off + ihl) {
                        p.addressType = "IPv4";
                        p.source.ip = ipv4Text(data + off + 12);
                        p.destination.ip = ipv4Text(data + off + 16);

                        unsigned proto = data[off + 9];
                        size_t transport = off + ihl;

                        if (proto == 6) p.protocol = "TCP";
                        else if (proto == 17) p.protocol = "UDP";
                        else if (proto == 1) p.protocol = "ICMP";
                        else p.protocol = "IPv4";

                        if ((proto == 6 || proto == 17) &&
                            n >= transport + 4) {
                            p.source.port = to_string(
                                (unsigned(data[transport]) << 8)
                                | data[transport + 1]);
                            p.destination.port = to_string(
                                (unsigned(data[transport + 2]) << 8)
                                | data[transport + 3]);
                        }
                    }
                } else if (type == 0x86dd && n >= off + 40) {
                    p.addressType = "IPv6";
                    p.source.ip = ipv6Text(data + off + 8);
                    p.destination.ip = ipv6Text(data + off + 24);

                    unsigned next = data[off + 6];
                    size_t transport = off + 40;

                    if (next == 6) p.protocol = "TCP";
                    else if (next == 17) p.protocol = "UDP";
                    else if (next == 58) p.protocol = "ICMPv6";
                    else p.protocol = "IPv6";

                    // Chi doc port khi header TCP/UDP nam ngay
                    // sau IPv6 header co ban; chua duyet extension headers.
                    if ((next == 6 || next == 17) &&
                        n >= transport + 4) {
                        p.source.port = to_string(
                            (unsigned(data[transport]) << 8)
                            | data[transport + 1]);
                        p.destination.port = to_string(
                            (unsigned(data[transport + 2]) << 8)
                            | data[transport + 3]);
                    }
                }
            }

            packets.push_back(p);
        }

        time_t now = time(nullptr);
        if (now != lastReport) {
            unsigned long long packetDelta =
                totalPackets - lastReportPackets;
            unsigned long long byteDelta =
                totalBytes - lastReportBytes;

            cout << "\n[" << put_time(localtime(&now), "%H:%M:%S")
                 << "] Tong goi: " << totalPackets
                 << " | Byte bat duoc: " << totalBytes
                 << " | Goi/giay gan day: " << packetDelta
                 << " | Byte/giay gan day: " << byteDelta
                 << '\n';

            lastReportPackets = totalPackets;
            lastReportBytes = totalBytes;
            lastReport = now;
        }
    }

    pcap_close(handle);

    cout << "\nDa dung bat goi.\n";
    cout << "Tong so goi: " << totalPackets << '\n';
    cout << "Tong byte bat duoc: " << totalBytes << '\n';

    string ipFilter, portFilter, protocolFilter;
    cout << "\nIP nguon/dich (Enter = tat ca): ";
    getline(cin >> ws, ipFilter);
    cout << "Cong nguon/dich (Enter = tat ca): ";
    getline(cin, portFilter);
    cout << "Giao thuc (TCP/UDP/ICMP/ARP/IPv4/IPv6; Enter = tat ca): ";
    getline(cin, protocolFilter);

    ipFilter = trim(ipFilter);
    portFilter = trim(portFilter);
    protocolFilter = trim(protocolFilter);

    vector<Packet> filtered;
    for (const auto& p : packets) {
        bool ipMatch =
            containsInsensitive(p.source.ip, ipFilter) ||
            containsInsensitive(p.destination.ip, ipFilter);
        bool portMatch =
            containsInsensitive(p.source.port, portFilter) ||
            containsInsensitive(p.destination.port, portFilter);
        bool protocolMatch =
            containsInsensitive(p.protocol, protocolFilter) ||
            containsInsensitive(p.addressType, protocolFilter);

        if (ipMatch && portMatch && protocolMatch)
            filtered.push_back(p);
    }

    cout << "\n--- GOI TIN DA LOC (TOI DA 30 DONG) ---\n";
    cout << left << setw(5) << "STT" << setw(8) << "Loai"
         << setw(10) << "Giao thuc" << setw(40) << "IP nguon"
         << setw(12) << "Cong nguon" << setw(40) << "IP dich"
         << setw(12) << "Cong dich" << setw(10) << "Do dai" << '\n';

    size_t shown = min<size_t>(30, filtered.size());
    for (size_t i = 0; i < shown; ++i) {
        const Packet& p = filtered[i];
        cout << left << setw(5) << i + 1
             << setw(8) << p.addressType
             << setw(10) << p.protocol
             << setw(40) << p.source.ip
             << setw(12) << p.source.port
             << setw(40) << p.destination.ip
             << setw(12) << p.destination.port
             << setw(10) << p.sizeText << '\n';
    }

    cout << "So goi phu hop: " << filtered.size() << '\n';

    cout << "Xuat cac goi da loc ra CSV? (y/n): ";
    string answer;
    getline(cin, answer);

    if (!answer.empty() && (answer[0] == 'y' || answer[0] == 'Y')) {
        string csvName;
        cout << "Ten file CSV (Enter = live_packets.csv): ";
        getline(cin, csvName);
        csvName = trim(csvName);
        if (csvName.empty()) csvName = "live_packets.csv";
        if (csvName.size() < 4 ||
            toLower(csvName.substr(csvName.size() - 4)) != ".csv")
            csvName += ".csv";

        ofstream csv(csvName, ios::binary);
        if (!csv) {
            cerr << "Khong tao duoc CSV: " << csvName << '\n';
            return 1;
        }

        csv << "STT,Loai,Giao thuc,IP nguon,Cong nguon,"
               "IP dich,Cong dich,Do dai (byte)\r\n";

        for (size_t i = 0; i < filtered.size(); ++i) {
            const Packet& p = filtered[i];
            csv << i + 1 << ',' << csvEscape(p.addressType) << ','
                << csvEscape(p.protocol) << ','
                << csvEscape(p.source.ip) << ','
                << csvEscape(p.source.port) << ','
                << csvEscape(p.destination.ip) << ','
                << csvEscape(p.destination.port) << ','
                << csvEscape(p.sizeText) << "\r\n";
        }

        cout << "Da xuat " << filtered.size()
             << " goi ra " << csvName << '\n';
    }

    return 0;
}

int main() {
    cout << "============================================\n";
    cout << "             LAN MONITOR\n";
    cout << "============================================\n";
    cout << "1. Phan tich file capture_utf8.txt\n";
    cout << "2. Bat goi truc tiep bang Npcap\n";
    cout << "Chon che do (1/2): ";

    string mode;
    getline(cin, mode);

    if (mode == "2")
        return runLiveCapture();

    if (!mode.empty() && mode != "1") {
        cerr << "Lua chon khong hop le.\n";
        return 1;
    }

    const string fileName = "capture_utf8.txt";
    ifstream file(fileName);

    if (!file.is_open()) {
        cerr << "Khong mo duoc file " << fileName << "!\n";
        cerr << "Hay dat capture_utf8.txt trong thu muc C:\\LANMonitor\n";
        return 1;
    }

    string line;
    long long eventCount = 0;
    long long totalBytes = 0;
    long long unknownSizes = 0;
    map<string, Statistics> addressStats;
    map<string, Statistics> protocolStats;
    vector<Packet> packets;

    while (getline(file, line)) {
        if (line.empty()) continue;

        if (line.find("PktGroupId") != string::npos ||
            line.find("PktNumber") != string::npos ||
            line.find("Component") != string::npos) {
            eventCount++;
        }

        if (line.find("ethertype ") == string::npos) continue;

        Packet packet;
        packet.addressType = getAddressType(line);
        packet.protocol = getProtocol(line);
        packet.sizeText = getPacketSize(line);
        packet.bytes = parseSize(packet.sizeText);
        packet.source = getSourceEndpoint(line);
        packet.destination = getDestinationEndpoint(line);

        totalBytes += packet.bytes;
        if (packet.sizeText == "-") unknownSizes++;
        addressStats[packet.addressType].count++;
        addressStats[packet.addressType].bytes += packet.bytes;
        protocolStats[packet.protocol].count++;
        protocolStats[packet.protocol].bytes += packet.bytes;
        packets.push_back(packet);
    }
    file.close();

    cout << "============================================\n";
    cout << "       LAN MONITOR - PHAN TICH GOI TIN\n";
    cout << "============================================\n";
    cout << "File log: " << fileName << "\n\n";
    cout << "--- THONG KE TONG QUAN ---\n";
    cout << "So su kien PktMon:       " << eventCount << '\n';
    cout << "So dong mo ta goi tin:   " << packets.size() << '\n';
    cout << "Tong do dai (byte):      " << totalBytes << '\n';
    cout << "Dong khong ro do dai:    " << unknownSizes << "\n\n";

    cout << "--- THONG KE THEO LOAI DIA CHI ---\n";
    cout << left << setw(15) << "Loai dia chi" << setw(15) << "So dong"
         << setw(20) << "Tong byte" << '\n';
    cout << string(50, '-') << '\n';
    for (const auto& item : addressStats) {
        cout << left << setw(15) << item.first << setw(15) << item.second.count
             << setw(20) << item.second.bytes << '\n';
    }

    cout << "\n--- THONG KE THEO GIAO THUC ---\n";
    cout << left << setw(15) << "Giao thuc" << setw(15) << "So dong"
         << setw(20) << "Tong byte" << '\n';
    cout << string(50, '-') << '\n';
    for (const auto& item : protocolStats) {
        cout << left << setw(15) << item.first << setw(15) << item.second.count
             << setw(20) << item.second.bytes << '\n';
    }

    string ipFilter, portFilter, protocolFilter;
    cout << "\n--- BO LOC GOI TIN ---\n";
    cout << "IP nguon/dich (Enter hoac - = tat ca): ";
    getline(cin, ipFilter);
    cout << "Cong nguon/dich (Enter hoac - = tat ca): ";
    getline(cin, portFilter);
    cout << "Giao thuc (TCP/UDP/ICMP/ARP/IPv4/IPv6; Enter hoac - = tat ca): ";
    getline(cin, protocolFilter);
    ipFilter = trim(ipFilter);
    portFilter = trim(portFilter);
    protocolFilter = trim(protocolFilter);

    vector<Packet> filtered;
    for (const auto& p : packets) {
        bool ipMatch = containsInsensitive(p.source.ip, ipFilter) ||
                       containsInsensitive(p.destination.ip, ipFilter);
        bool portMatch = containsInsensitive(p.source.port, portFilter) ||
                         containsInsensitive(p.destination.port, portFilter);
        bool protocolMatch = containsInsensitive(p.protocol, protocolFilter) ||
                            containsInsensitive(p.addressType, protocolFilter);
        if (ipMatch && portMatch && protocolMatch) filtered.push_back(p);
    }

    cout << "\n--- CHI TIET GOI TIN DA LOC (TOI DA 30 DONG) ---\n";
    cout << left << setw(5) << "STT" << setw(8) << "Loai"
         << setw(10) << "Giao thuc" << setw(40) << "IP nguon"
         << setw(12) << "Cong nguon" << setw(40) << "IP dich"
         << setw(12) << "Cong dich" << setw(10) << "Do dai" << '\n';
    cout << string(137, '-') << '\n';

    size_t shown = min<size_t>(30, filtered.size());
    for (size_t i = 0; i < shown; ++i) {
        const Packet& p = filtered[i];
        cout << left << setw(5) << i + 1 << setw(8) << p.addressType
             << setw(10) << p.protocol << setw(40) << p.source.ip
             << setw(12) << p.source.port << setw(40) << p.destination.ip
             << setw(12) << p.destination.port << setw(10) << p.sizeText << '\n';
    }
    cout << "\nSo goi tin phu hop voi bo loc: " << filtered.size() << '\n';
    cout << "Da hien thi " << shown << " dong.\n";

    cout << "\nBan co muon xuat cac goi tin da loc ra CSV? (y/n): ";
    string answer;
    getline(cin, answer);
    if (!answer.empty() && (answer[0] == 'y' || answer[0] == 'Y')) {
        string csvName;
        cout << "Ten file CSV (Enter = filtered_packets.csv): ";
        getline(cin, csvName);
        csvName = trim(csvName);
        if (csvName.empty()) csvName = "filtered_packets.csv";
        if (csvName.size() < 4 || toLower(csvName.substr(csvName.size() - 4)) != ".csv")
            csvName += ".csv";

        ofstream csv(csvName, ios::binary);
        if (!csv.is_open()) {
            cerr << "Khong tao duoc file CSV: " << csvName << '\n';
            return 1;
        }
        csv << "STT,Loai,Giao thuc,IP nguon,Cong nguon,IP dich,Cong dich,Do dai (byte)\r\n";
        for (size_t i = 0; i < filtered.size(); ++i) {
            const Packet& p = filtered[i];
            csv << i + 1 << ',' << csvEscape(p.addressType) << ','
                << csvEscape(p.protocol) << ',' << csvEscape(p.source.ip) << ','
                << csvEscape(p.source.port) << ',' << csvEscape(p.destination.ip) << ','
                << csvEscape(p.destination.port) << ',' << csvEscape(p.sizeText) << "\r\n";
        }
        csv.close();
        cout << "Da xuat " << filtered.size() << " goi tin ra: " << csvName << '\n';
    }

    cout << "\nPhan tich hoan tat.\n";
    return 0;
}