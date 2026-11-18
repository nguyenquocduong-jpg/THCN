#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <algorithm>
#include <cctype>
#include <vector>
#include <pcap.h>
#include <cstdint>
#include <limits>
#include <cstdio>
#include <ctime>
#include <conio.h>

using namespace std;

struct Endpoint {
    string ip = "-";
    string port = "-";
};

struct Statistics {
    long long count = 0;
    long long bytes = 0;
};

struct Packet {
    string addressType = "Khac";
    string protocol = "OTHER";
    Endpoint source;
    Endpoint destination;
    string sizeText = "-";
    long long bytes = 0;
    string timestamp;
};

string trim(const string& s) {
    size_t first = s.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = s.find_last_not_of(" \t\r\n");
    return s.substr(first, last - first + 1);
}
string extractTimestamp(const string& line) {
    // Log PktMon co dang:
    // [00]0000.0000::2026-10-22 11:09:53.738645500 [Microsoft-Windows-PktMon]
    size_t pos = line.find("::");
    if (pos == string::npos) return "";

    pos += 2;

    // Timestamp co dang YYYY-MM-DD HH:MM:SS
    // va co the co phan thap phan sau giay.
    if (line.size() < pos + 19) return "";

    string timestamp = line.substr(pos, 19);

    if (timestamp[4] != '-' || timestamp[7] != '-' ||
        timestamp[10] != ' ' || timestamp[13] != ':' ||
        timestamp[16] != ':') {
        return "";
    }

    return timestamp;
}
string toLower(string s) {
    transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(tolower(c)); });
    return s;
}

string currentTimestamp() {
    time_t now = time(nullptr);
    tm localTime{};
#ifdef _WIN32
    localtime_s(&localTime, &now);
#else
    localtime_r(&now, &localTime);
#endif
    ostringstream out;
    out << put_time(&localTime, "%Y-%m-%d %H:%M:%S");
    return out.str();
}

string getPacketDescription(const string& line) {
    size_t ethertype = line.find("ethertype ");
    if (ethertype == string::npos) return "";
    size_t colon = line.find(": ", ethertype);
    if (colon == string::npos) return "";
    return trim(line.substr(colon + 2));
}

string getPacketSize(const string& line) {
    size_t pos = line.find("length ");
    if (pos == string::npos) return "-";
    pos += 7;
    size_t end = pos;
    while (end < line.size() &&
           isdigit(static_cast<unsigned char>(line[end]))) ++end;
    if (end == pos) return "-";
    return line.substr(pos, end - pos);
}

long long parseSize(const string& s) {
    try { return stoll(s); } catch (...) { return 0; }
}

string getAddressType(const string& line) {
    string lower = toLower(line);
    if (lower.find("ethertype ipv4") != string::npos ||
        lower.find("ethertype ip (") != string::npos) return "IPv4";
    if (lower.find("ethertype ipv6") != string::npos) return "IPv6";
    if (lower.find("ethertype arp") != string::npos) return "ARP";
    return "Khac";
}

string getProtocol(const string& line) {
    string lower = toLower(line);
    string desc = toLower(getPacketDescription(line));
    if (lower.find("ethertype arp") != string::npos) return "ARP";
    if (desc.find("icmp6") != string::npos ||
        desc.find("icmpv6") != string::npos) return "ICMPv6";
    if (desc.find("icmp") != string::npos) return "ICMP";
    if (desc.find("tcp") != string::npos ||
        desc.find("flags [") != string::npos) return "TCP";
    if (desc.find("udp") != string::npos ||
        desc.find(" a? ") != string::npos ||
        desc.find(" aaaa? ") != string::npos ||
        desc.find(" mdns") != string::npos) return "UDP";
    return "Khac";
}

Endpoint parseEndpoint(const string& endpoint) {
    string value = trim(endpoint);
    Endpoint result;
    if (value.empty()) return result;

    while (!value.empty() &&
           (value.back() == ',' || value.back() == ';')) value.pop_back();

    // tcpdump-style IPv6 endpoints often append ".port".
    if (value.find(':') != string::npos) {
        size_t dot = value.rfind('.');
        if (dot != string::npos && dot + 1 < value.size()) {
            string candidate = value.substr(dot + 1);
            bool digits = all_of(candidate.begin(), candidate.end(),
                [](unsigned char c) { return isdigit(c); });
            if (digits) {
                result.ip = value.substr(0, dot);
                result.port = candidate;
                return result;
            }
        }
        result.ip = value;
        return result;
    }

    size_t dots = count(value.begin(), value.end(), '.');
    if (dots >= 4) {
        size_t dot = value.rfind('.');
        string candidate = value.substr(dot + 1);
        bool digits = !candidate.empty() &&
            all_of(candidate.begin(), candidate.end(),
                [](unsigned char c) { return isdigit(c); });
        if (digits) {
            result.ip = value.substr(0, dot);
            result.port = candidate;
            return result;
        }
    }
    result.ip = value;
    return result;
}

Endpoint getSourceEndpoint(const string& line) {
    string desc = getPacketDescription(line);
    size_t arrow = desc.find(" > ");
    if (arrow == string::npos) return {};
    return parseEndpoint(desc.substr(0, arrow));
}

Endpoint getDestinationEndpoint(const string& line) {
    string desc = getPacketDescription(line);
    size_t arrow = desc.find(" > ");
    if (arrow == string::npos) return {};

    size_t start = arrow + 3;
    size_t end = string::npos;
    const string markers[] = {
        ": UDP,", ": TCP,", ": ICMP,", ": ICMP6,", ": ICMP6 ",
        ": Flags [", ": UDP ", ": TCP ", ": ICMP ", ", seq ",
        ", ack ", ", win ", ", length "
    };
    for (const string& marker : markers) {
        size_t found = desc.find(marker, start);
        if (found != string::npos && (end == string::npos || found < end))
            end = found;
    }
    if (end == string::npos) {
        size_t colonSpace = desc.find(": ", start);
        if (colonSpace != string::npos) end = colonSpace;
    }
    if (end == string::npos) return {};
    return parseEndpoint(desc.substr(start, end - start));
}

string csvEscape(const string& value) {
    string out = "\"";
    for (char c : value) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += '"';
    return out;
}

// Loc chinh xac (khong tim chuoi con) de tranh nhap cong 3 ma khop 443/5353.
bool matchesExactInsensitive(const string& value, const string& filter) {
    if (filter.empty() || trim(filter) == "-") return true;
    return toLower(trim(value)) == toLower(trim(filter));
}

string ipv4Text(const u_char* p) {
    char b[32];
    snprintf(b, sizeof(b), "%u.%u.%u.%u",
        (unsigned)p[0], (unsigned)p[1], (unsigned)p[2], (unsigned)p[3]);
    return b;
}

string ipv6Text(const u_char* p) {
    unsigned short groups[8];
    for (int i = 0; i < 8; ++i)
        groups[i] = (unsigned(p[i * 2]) << 8) | unsigned(p[i * 2 + 1]);

    int bestStart = -1, bestLen = 1;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) { ++i; continue; }
        int j = i;
        while (j < 8 && groups[j] == 0) ++j;
        if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
        i = j;
    }

    if (bestStart == -1) {
        ostringstream out;
        out << hex << nouppercase;
        for (int i = 0; i < 8; ++i) {
            if (i) out << ':';
            out << groups[i];
        }
        return out.str();
    }

    string result;
    for (int i = 0; i < bestStart; ++i) {
        if (!result.empty()) result += ':';
        ostringstream part;
        part << hex << nouppercase << groups[i];
        result += part.str();
    }
    result += "::";
    for (int i = bestStart + bestLen; i < 8; ++i) {
        if (i > bestStart + bestLen) result += ':';
        ostringstream part;
        part << hex << nouppercase << groups[i];
        result += part.str();
    }
    return result;
}

void writeCsvHeader(ofstream& csv) {
    csv << "STT,Thoi gian,Loai,Giao thuc,IP nguon,Cong nguon,"
           "IP dich,Cong dich,Do dai (byte)\r\n";
}

void writeCsvPacket(ofstream& csv, size_t index, const Packet& p) {
    csv << index << ','
        << csvEscape(p.timestamp) << ','
        << csvEscape(p.addressType) << ','
        << csvEscape(p.protocol) << ','
        << csvEscape(p.source.ip) << ','
        << csvEscape(p.source.port) << ','
        << csvEscape(p.destination.ip) << ','
        << csvEscape(p.destination.port) << ','
        << p.bytes << "\r\n";
}

vector<Packet> filterPackets(const vector<Packet>& packets,
                             const string& ipFilter,
                             const string& portFilter,
                             const string& protocolFilter) {
    vector<Packet> filtered;
    for (const auto& p : packets) {
        bool ipMatch = matchesExactInsensitive(p.source.ip, ipFilter) ||
                       matchesExactInsensitive(p.destination.ip, ipFilter);
        bool portMatch = matchesExactInsensitive(p.source.port, portFilter) ||
                         matchesExactInsensitive(p.destination.port, portFilter);
        bool protocolMatch = matchesExactInsensitive(p.protocol, protocolFilter) ||
                             matchesExactInsensitive(p.addressType, protocolFilter);
        if (ipMatch && portMatch && protocolMatch) filtered.push_back(p);
    }
    return filtered;
}

void showPackets(const vector<Packet>& packets, size_t maxRows = 30) {
    cout << "\n--- GOI TIN DA LOC (TOI DA " << maxRows << " DONG) ---\n";
    cout << left << setw(5) << "STT" << setw(20) << "Thoi gian"
         << setw(8) << "Loai" << setw(10) << "Giao thuc"
         << setw(40) << "IP nguon" << setw(12) << "Cong nguon"
         << setw(40) << "IP dich" << setw(12) << "Cong dich"
         << setw(12) << "Do dai" << '\n';
    size_t shown = min(maxRows, packets.size());
    for (size_t i = 0; i < shown; ++i) {
        const Packet& p = packets[i];
        cout << left << setw(5) << i + 1 << setw(20) << p.timestamp
             << setw(8) << p.addressType << setw(10) << p.protocol
             << setw(40) << p.source.ip << setw(12) << p.source.port
             << setw(40) << p.destination.ip << setw(12) << p.destination.port
             << setw(12) << p.sizeText << '\n';
    }
    cout << "So goi phu hop: " << packets.size() << '\n';
}

bool exportCsv(const vector<Packet>& packets, const string& defaultName) {
    cout << "Xuat cac goi da loc ra CSV? (y/n): ";
    string answer;
    getline(cin, answer);
    if (answer.empty() || (answer[0] != 'y' && answer[0] != 'Y')) return true;

    cout << "Ten file CSV (Enter = " << defaultName << "): ";
    string name;
    getline(cin, name);
    name = trim(name);
    if (name.empty()) name = defaultName;
    if (name.size() < 4 || toLower(name.substr(name.size() - 4)) != ".csv")
        name += ".csv";

    ofstream csv(name, ios::binary);
    if (!csv) {
        cerr << "Khong tao duoc file CSV: " << name << '\n';
        return false;
    }
    writeCsvHeader(csv);
    for (size_t i = 0; i < packets.size(); ++i)
        writeCsvPacket(csv, i + 1, packets[i]);
    csv.close();
    cout << "Da xuat " << packets.size() << " goi ra " << name << '\n';
    return true;
}
  
void showLiveStatistics(const vector<Packet>& packets) {
    map<string, Statistics> protocolStats;
    map<string, Statistics> sourceStats;
    long long totalBytes = 0;

    for (const auto& p : packets) {
        protocolStats[p.protocol].count++;
        protocolStats[p.protocol].bytes += p.bytes;
        totalBytes += p.bytes;

        if (p.source.ip != "-" && !p.source.ip.empty()) {
            sourceStats[p.source.ip].count++;
            sourceStats[p.source.ip].bytes += p.bytes;
        }
    }

    cout << "\n--- THONG KE THEO GIAO THUC ---\n";
    cout << left << setw(15) << "Giao thuc"
         << right << setw(12) << "So goi"
         << setw(12) << "% goi"
         << setw(18) << "Tong byte"
         << setw(12) << "% byte" << '\n';
    cout << string(69, '-') << '\n';

    for (const auto& item : protocolStats) {
        double packetPct = packets.empty() ? 0.0
            : 100.0 * static_cast<double>(item.second.count) / packets.size();
        double bytePct = totalBytes == 0 ? 0.0
            : 100.0 * static_cast<double>(item.second.bytes) / totalBytes;

        cout << left << setw(15) << item.first
             << right << setw(12) << item.second.count
             << setw(11) << fixed << setprecision(2) << packetPct << "%"
             << setw(18) << item.second.bytes
             << setw(11) << fixed << setprecision(2) << bytePct << "%\n";
    }
    cout << "Tong goi phu hop: " << packets.size()
         << " | Tong byte: " << totalBytes << '\n';

    vector<pair<string, Statistics>> topSources(
        sourceStats.begin(), sourceStats.end());

    sort(topSources.begin(), topSources.end(),
        [](const auto& a, const auto& b) {
            if (a.second.count != b.second.count)
                return a.second.count > b.second.count;
            return a.second.bytes > b.second.bytes;
        });

    cout << "\n--- TOP 10 IP NGUON ---\n";
    cout << left << setw(40) << "IP nguon"
         << right << setw(12) << "So goi"
         << setw(12) << "% goi"
         << setw(18) << "Tong byte" << '\n';
    cout << string(82, '-') << '\n';

    size_t limit = min<size_t>(10, topSources.size());
    for (size_t i = 0; i < limit; ++i) {
        double packetPct = packets.empty() ? 0.0
            : 100.0 * static_cast<double>(topSources[i].second.count) / packets.size();
        cout << left << setw(40) << topSources[i].first
             << right << setw(12) << topSources[i].second.count
             << setw(11) << fixed << setprecision(2) << packetPct << "%"
             << setw(18) << topSources[i].second.bytes << '\n';
    }
}

bool exportStatisticsCsv(const vector<Packet>& packets,
                         const string& fileName) {
    map<string, Statistics> protocolStats;
    map<string, Statistics> sourceStats;

    for (const auto& p : packets) {
        protocolStats[p.protocol].count++;
        protocolStats[p.protocol].bytes += p.bytes;

        if (p.source.ip != "-" && !p.source.ip.empty()) {
            sourceStats[p.source.ip].count++;
            sourceStats[p.source.ip].bytes += p.bytes;
        }
    }

    ofstream csv(fileName, ios::binary);
    if (!csv) {
        cerr << "Khong tao duoc bao cao: " << fileName << '\n';
        return false;
    }

    csv << "Loai thong ke,Gia tri,So goi,Tong byte,Ty le so goi (%)\r\n";
    for (const auto& item : protocolStats) {
        double pct = packets.empty() ? 0.0
            : 100.0 * static_cast<double>(item.second.count) / packets.size();
        csv << csvEscape("Giao thuc") << ','
            << csvEscape(item.first) << ','
            << item.second.count << ','
            << item.second.bytes << ','
            << fixed << setprecision(2) << pct << "\r\n";
    }

    vector<pair<string, Statistics>> topSources(
        sourceStats.begin(), sourceStats.end());

    sort(topSources.begin(), topSources.end(),
        [](const auto& a, const auto& b) {
            if (a.second.count != b.second.count)
                return a.second.count > b.second.count;
            return a.second.bytes > b.second.bytes;
        });

    size_t limit = min<size_t>(10, topSources.size());
    for (size_t i = 0; i < limit; ++i) {
        double pct = packets.empty() ? 0.0
            : 100.0 * static_cast<double>(topSources[i].second.count) / packets.size();
        csv << csvEscape("IP nguon") << ','
            << csvEscape(topSources[i].first) << ','
            << topSources[i].second.count << ','
            << topSources[i].second.bytes << ','
            << fixed << setprecision(2) << pct << "\r\n";
    }

    csv.close();
    if (!csv) {
        cerr << "Loi khi ghi bao cao: " << fileName << '\n';
        return false;
    }
    cout << "Da xuat bao cao thong ke: " << fileName << '\n';
    return true;
}

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
        cout << count << ". " << (d->description ? d->description : d->name) << '\n';
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
    // Remove the newline left by cin >> choice before any later getline().
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    pcap_if_t* selected = devices;
    for (int i = 1; i < choice; ++i) selected = selected->next;
    if (!selected->name) {
        pcap_freealldevs(devices);
        cerr << "Adapter khong co ten.\n";
        return 1;
    }
    string deviceName = selected->name;
    pcap_freealldevs(devices);

    char openError[PCAP_ERRBUF_SIZE] = {};
    pcap_t* handle = pcap_open_live(deviceName.c_str(), 65536, 1, 250, openError);
    if (!handle) {
        cerr << "Khong mo duoc adapter: " << openError << '\n';
        cerr << "Hay thu mo PowerShell bang Run as administrator.\n";
        return 1;
    }

    int linkType = pcap_datalink(handle);
    cout << "Kieu lien ket (DLT): " << linkType << '\n';
    if (linkType != DLT_EN10MB) {
        cerr << "Adapter nay khong tra ve khung Ethernet. Hay thu adapter khac.\n";
        pcap_close(handle);
        return 1;
    }

    vector<Packet> packets;
    unsigned long long totalBytes = 0, totalPackets = 0;
    unsigned long long lastReportPackets = 0, lastReportBytes = 0;
    time_t lastReport = time(nullptr);

    cout << "\nDang bat goi. Nhan q de dung.\n";
    cout << "Chi giam sat luu luong tren adapter da chon.\n";

    while (true) {
        if (_kbhit()) {
            int key = _getch();
            if (key == 'q' || key == 'Q') break;
        }

        pcap_pkthdr* header = nullptr;
        const u_char* data = nullptr;
        int result = pcap_next_ex(handle, &header, &data);
        if (result == -1) {
            cerr << "\nLoi khi bat goi: " << pcap_geterr(handle) << '\n';
            break;
        }

        if (result == 1 && header && data) {
            ++totalPackets;
            totalBytes += header->caplen;

            Packet p;
            p.timestamp = currentTimestamp();
            p.bytes = header->len;
            p.sizeText = to_string(header->len);

            size_t n = header->caplen;
            size_t off = 14;
            if (n >= 14) {
                unsigned int type = (unsigned(data[12]) << 8) | data[13];
                while ((type == 0x8100 || type == 0x88a8) && n >= off + 4) {
                    type = (unsigned(data[off + 2]) << 8) | data[off + 3];
                    off += 4;
                }

                if (type == 0x0806) { // ARP
                    p.addressType = "ARP";
                    p.protocol = "ARP";
                    if (n >= off + 28) {
                        unsigned int htype = (unsigned(data[off]) << 8) | data[off + 1];
                        unsigned int ptype = (unsigned(data[off + 2]) << 8) | data[off + 3];
                        unsigned int hlen = data[off + 4], plen = data[off + 5];
                        if (htype == 1 && ptype == 0x0800 && hlen == 6 && plen == 4) {
                            p.source.ip = ipv4Text(data + off + 14);
                            p.destination.ip = ipv4Text(data + off + 24);
                        }
                    }
                } else if (type == 0x0800 && n >= off + 20) { // IPv4
                    unsigned int version = data[off] >> 4;
                    unsigned int ihl = (data[off] & 0x0F) * 4;
                    if (version == 4 && ihl >= 20 && n >= off + ihl) {
                        p.addressType = "IPv4";
                        p.source.ip = ipv4Text(data + off + 12);
                        p.destination.ip = ipv4Text(data + off + 16);
                        unsigned int proto = data[off + 9];
                        size_t transport = off + ihl;
                        if (proto == 6) p.protocol = "TCP";
                        else if (proto == 17) p.protocol = "UDP";
                        else if (proto == 1) p.protocol = "ICMP";
                        else p.protocol = "IPv4";

                        unsigned int fragment = (unsigned(data[off + 6]) << 8) | data[off + 7];
                        bool firstFragment = (fragment & 0x1FFF) == 0;
                        if ((proto == 6 || proto == 17) && firstFragment &&
                            n >= transport + 4) {
                            p.source.port = to_string((unsigned(data[transport]) << 8) |
                                                      data[transport + 1]);
                            p.destination.port = to_string((unsigned(data[transport + 2]) << 8) |
                                                           data[transport + 3]);
                        }
                    }
                } else if (type == 0x86dd && n >= off + 40 &&
                           (data[off] >> 4) == 6) { // IPv6
                    p.addressType = "IPv6";
                    p.source.ip = ipv6Text(data + off + 8);
                    p.destination.ip = ipv6Text(data + off + 24);
                    unsigned int next = data[off + 6];
                    size_t transport = off + 40;
                    bool valid = true, nonInitialFragment = false;

                    for (int i = 0; i < 8; ++i) {
                        if (next == 0 || next == 43 || next == 60 ||
                            next == 135 || next == 139 || next == 140) {
                            if (transport + 2 > n) { valid = false; break; }
                            size_t len = (size_t(data[transport + 1]) + 1) * 8;
                            if (len < 8 || transport + len > n) { valid = false; break; }
                            next = data[transport];
                            transport += len;
                        } else if (next == 44) {
                            if (transport + 8 > n) { valid = false; break; }
                            unsigned int fragField = (unsigned(data[transport + 2]) << 8) |
                                                     data[transport + 3];
                            if ((fragField & 0xFFF8) != 0) nonInitialFragment = true;
                            next = data[transport];
                            transport += 8;
                        } else if (next == 51) {
                            if (transport + 2 > n) { valid = false; break; }
                            size_t len = (size_t(data[transport + 1]) + 2) * 4;
                            if (len < 8 || transport + len > n) { valid = false; break; }
                            next = data[transport];
                            transport += len;
                        } else {
                            break;
                        }
                    }

                    if (next == 6) p.protocol = "TCP";
                    else if (next == 17) p.protocol = "UDP";
                    else if (next == 58) p.protocol = "ICMPv6";
                    else p.protocol = "IPv6";

                    if (valid && !nonInitialFragment && (next == 6 || next == 17) &&
                        transport + 4 <= n) {
                        p.source.port = to_string((unsigned(data[transport]) << 8) |
                                                  data[transport + 1]);
                        p.destination.port = to_string((unsigned(data[transport + 2]) << 8) |
                                                       data[transport + 3]);
                    }
                }
            }

            packets.push_back(p);
        }

        time_t now = time(nullptr);
        if (now != lastReport) {
            unsigned long long packetDelta = totalPackets - lastReportPackets;
            unsigned long long byteDelta = totalBytes - lastReportBytes;
            tm localTime{};
#ifdef _WIN32
            localtime_s(&localTime, &now);
#else
            localtime_r(&now, &localTime);
#endif
            cout << "\n[" << put_time(&localTime, "%H:%M:%S")
                 << "] Tong goi: " << totalPackets
                 << " | Byte bat duoc: " << totalBytes
                 << " | Goi/giay gan day: " << packetDelta
                 << " | Byte/giay gan day: " << byteDelta << '\n';
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
    cout << "\nIP nguon/dich chinh xac (Enter = tat ca): " << flush;
    if (!getline(cin, ipFilter)) {
        cerr << "\nLoi doc bo loc IP.\n";
        return 1;
    }
    cout << "Cong nguon/dich chinh xac (Enter = tat ca): " << flush;
    if (!getline(cin, portFilter)) {
        cerr << "\nLoi doc bo loc cong.\n";
        return 1;
    }
    cout << "Giao thuc (TCP/UDP/ICMP/ICMPv6/ARP/IPv4/IPv6; Enter = tat ca): " << flush;
    if (!getline(cin, protocolFilter)) {
        cerr << "\nLoi doc bo loc giao thuc.\n";
        return 1;
    }

    ipFilter = trim(ipFilter);
    portFilter = trim(portFilter);
    protocolFilter = trim(protocolFilter);
    vector<Packet> filtered = filterPackets(packets, ipFilter, portFilter, protocolFilter);
    showPackets(filtered);

    cout << "\n--- THONG KE GOI DA LOC ---\n";
    showLiveStatistics(filtered);

    exportCsv(filtered, "live_packets.csv");
    bool statsExported = exportStatisticsCsv(filtered, "live_statistics.csv");
    cout << (statsExported ? "Da xuat xong bao cao thong ke.\n"
                          : "Xuat bao cao thong ke that bai.\n");

    return 0;
}

int runFileAnalysis() {
    const string fileName = "capture_utf8.txt";
    ifstream file(fileName);
    if (!file.is_open()) {
        cerr << "Khong mo duoc file " << fileName << "!\n";
        cerr << "Hay dat capture_utf8.txt trong thu muc C:\\LANMonitor\n";
        return 1;
    }

    string line;
string currentFileTimestamp;
long long eventCount = 0, totalBytes = 0, unknownSizes = 0;
map<string, Statistics> addressStats, protocolStats;
vector<Packet> packets;

   while (getline(file, line)) {
    if (line.empty()) continue;

    // Luu timestamp tu dong tieu de su kien PktMon.
    string parsedTimestamp = extractTimestamp(line);
    if (!parsedTimestamp.empty()) {
        currentFileTimestamp = parsedTimestamp;
    }

    if (line.find("PktGroupId") != string::npos ||
        line.find("PktNumber") != string::npos ||
        line.find("Component") != string::npos) {
        ++eventCount;
    }

    // Chi xu ly dong mo ta goi tin.
    if (line.find("ethertype ") == string::npos) continue;

    Packet p;
    p.addressType = getAddressType(line);
    p.protocol = getProtocol(line);
    p.sizeText = getPacketSize(line);
    p.bytes = parseSize(p.sizeText);
    p.source = getSourceEndpoint(line);
    p.destination = getDestinationEndpoint(line);
    p.timestamp = currentFileTimestamp;

    totalBytes += p.bytes;
    if (p.sizeText == "-") ++unknownSizes;

    addressStats[p.addressType].count++;
    addressStats[p.addressType].bytes += p.bytes;
    protocolStats[p.protocol].count++;
    protocolStats[p.protocol].bytes += p.bytes;

    packets.push_back(p);
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
         << setw(20) << "Tong byte" << '\n' << string(50, '-') << '\n';
    for (const auto& item : addressStats)
        cout << left << setw(15) << item.first << setw(15) << item.second.count
             << setw(20) << item.second.bytes << '\n';

    cout << "\n--- THONG KE THEO GIAO THUC ---\n";
    cout << left << setw(15) << "Giao thuc" << setw(15) << "So dong"
         << setw(20) << "Tong byte" << '\n' << string(50, '-') << '\n';
    for (const auto& item : protocolStats)
        cout << left << setw(15) << item.first << setw(15) << item.second.count
             << setw(20) << item.second.bytes << '\n';

   
    string ipFilter, portFilter, protocolFilter;
    cout << "\n--- BO LOC GOI TIN ---\n";
    cout << "IP nguon/dich chinh xac (Enter = tat ca): " << flush;
    if (!getline(cin, ipFilter)) {
        cerr << "\nLoi doc bo loc IP.\n";
        return 1;
    }
    cout << "Cong nguon/dich chinh xac (Enter = tat ca): " << flush;
    if (!getline(cin, portFilter)) {
        cerr << "\nLoi doc bo loc cong.\n";
        return 1;
    }
    cout << "Giao thuc (TCP/UDP/ICMP/ICMPv6/ARP/IPv4/IPv6; Enter = tat ca): " << flush;
    if (!getline(cin, protocolFilter)) {
        cerr << "\nLoi doc bo loc giao thuc.\n";
        return 1;
    }

    ipFilter = trim(ipFilter);
    portFilter = trim(portFilter);
    protocolFilter = trim(protocolFilter);
    vector<Packet> filtered = filterPackets(packets, ipFilter, portFilter, protocolFilter);
    showPackets(filtered);
    showLiveStatistics(filtered);
    exportCsv(filtered, "file_packets.csv");
    if (!exportStatisticsCsv(filtered, "file_statistics.csv")) return 1;
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
    if (mode == "2") return runLiveCapture();
    if (mode.empty() || mode == "1") return runFileAnalysis();

    cerr << "Lua chon khong hop le.\n";
    return 1;
}