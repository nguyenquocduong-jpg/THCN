#include <iostream>
#include <cstdlib>
#include <limits>

using namespace std;

int main() {
    system("cls");

    cout << "====================================\n";
    cout << "       LAN MONITOR - DE TAI 1\n";
    cout << "====================================\n\n";

    cout << "[THONG TIN MANG]\n";
    cout << "Thong tin cac card mang tren may:\n\n";

    system("ipconfig");

    cout << "\n====================================\n";
    cout << "[TRANG THAI CHUONG TRINH]\n";
    cout << "Chuong trinh LAN Monitor dang chay.\n";
    cout << "Che do hien tai: Kiem tra thong tin mang.\n";
    cout << "Chuc nang bat goi tin: Chua kich hoat.\n";
    cout << "====================================\n";

    cout << "\nNhan Enter de thoat...";
    cin.get();

    return 0;
}