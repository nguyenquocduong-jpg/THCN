
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <map>
#include <algorithm>
#include <cctype>
#include <vector>

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

int main() {
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