#include <iostream>
#include <fstream>
#include <string>
using namespace std;

int main() {
    ifstream file("C:\\LANMonitor\\capture_utf8.txt");

    if (!file.is_open()) {
        cout << "Khong mo duoc file!\n";
        return 1;
    }

    string line;
    long long totalLines = 0;
    long long ipv4 = 0, ipv6 = 0, arp = 0, udp = 0;

    while (getline(file, line)) {
        totalLines++;

        if (line.find("ethertype IPv4") != string::npos)
            ipv4++;

        if (line.find("ethertype IPv6") != string::npos)
            ipv6++;

        if (line.find("ethertype ARP") != string::npos)
            arp++;

        if (line.find(": UDP,") != string::npos)
            udp++;
    }

    cout << "Tong so dong: " << totalLines << '\n';
    cout << "IPv4: " << ipv4 << '\n';
    cout << "IPv6: " << ipv6 << '\n';
    cout << "ARP:  " << arp << '\n';
    cout << "UDP:  " << udp << '\n';

    return 0;
}