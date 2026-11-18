#include <iostream>
#include <iomanip>
#include <cstdint>

using namespace std;

// Chuyen 4 byte dia chi IPv4 thanh dang a.b.c.d
void printIP(const uint8_t* ip) {
    cout << static_cast<int>(ip[0]) << "."
         << static_cast<int>(ip[1]) << "."
         << static_cast<int>(ip[2]) << "."
         << static_cast<int>(ip[3]);
}

// Phan tich header IPv4
void analyzeIPv4(const uint8_t* packet, size_t size) {
    if (size < 20 || (packet[0] >> 4) != 4) {
        cout << "Goi tin IPv4 khong hop le.\n";
        return;
    }

    size_t headerLength = (packet[0] & 0x0F) * 4;

    if (headerLength < 20 || size < headerLength) {
        cout << "Header IPv4 khong hop le.\n";
        return;
    }

    unsigned int totalLength =
        (static_cast<unsigned int>(packet[2]) << 8) | packet[3];

    cout << "\n[PHAN TICH GOI TIN IPv4]\n";

    cout << "IP nguon: ";
    printIP(packet + 12);

    cout << "\nIP dich: ";
    printIP(packet + 16);

    cout << "\nDo dai header: " << headerLength << " byte";
    cout << "\nDo dai goi tin IPv4: " << totalLength << " byte";

    cout << "\nGiao thuc: ";

    switch (packet[9]) {
        case 1:  cout << "ICMP"; break;
        case 6:  cout << "TCP";  break;
        case 17: cout << "UDP";  break;
        default: cout << "Khac (" << static_cast<int>(packet[9]) << ")";
    }

    cout << "\n";
}

int main() {
    cout << "====================================\n";
    cout << "       LAN MONITOR - DE TAI 1\n";
    cout << "====================================\n";

    // Goi IPv4 mau de thu nghiem bo phan tich.
    // Day la du lieu gia lap, khong phai goi tin truc tiep tu mang.
    const uint8_t samplePacket[] = {
        0x45, 0x00, 0x00, 0x1C,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        192, 168, 1, 14,
        8, 8, 8, 8,
        0x00, 0x35, 0x00, 0x35,
        0x00, 0x08, 0x00, 0x00
    };

    analyzeIPv4(samplePacket, sizeof(samplePacket));

    cout << "\nLuu y: Dang kiem thu bo phan tich bang goi tin mau.\n";
    cout << "Nhan Enter de thoat...";
    cin.get();

    return 0;
}