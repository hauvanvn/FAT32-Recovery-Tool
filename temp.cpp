#include <iostream>
#include <iomanip>
#include <string>
#include "FAT32.h"

using namespace std;

// Hàm phụ trợ để in Timestamp cho đẹp (Optional)
string formatTimestamp(uint32_t date, uint32_t time) {
    // FAT Date format: Year(7) | Month(4) | Day(5)
    int year = ((date >> 9) & 0x7F) + 1980;
    int month = (date >> 5) & 0x0F;
    int day = date & 0x1F;
    
    // FAT Time format: Hour(5) | Min(6) | Sec(5)
    int hour = (time >> 11) & 0x1F;
    int minute = (time >> 5) & 0x3F;
    int sec = (time & 0x1F) * 2;

    char buffer[30];
    sprintf(buffer, "%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, minute, sec);
    return string(buffer);
}

int main(int argc, char* argv[]) {
    // 1. Kiểm tra tham số đầu vào
    string diskPath = "VHDFAT32.vhd"; // Mặc định
    if (argc > 1) {
        diskPath = argv[1];
    }

    cout << "=== FAT32 IN-PLACE RECOVERY TOOL ===\n";
    cout << "Opening disk image: " << diskPath << "\n\n";

    try {
        // 2. Khởi tạo công cụ
        FAT32Recovery tool(diskPath);

        // 3. Đọc cấu trúc đĩa (MBR & Partition)
        tool.readMBR();
        tool.listPartition();

        // Giả sử ta chọn Partition đầu tiên (Index 0) để làm việc
        // Trong thực tế bạn có thể cho người dùng nhập cin >> partIndex
        int partIndex = 0; 
        cout << "\n>>> Selecting Partition " << partIndex << "...\n";
        
        tool.readBootSector(partIndex);
        tool.loadFAT(); // Tải bảng FAT vào RAM

        // 4. QUÉT VÀ PHÂN TÍCH (Analysis Phase)
        // Quét thư mục gốc (Root Cluster thường là 2)
        uint32_t currentDirCluster = 2; 
        cout << "\n>>> Analyzing Deleted Files in Root Directory (Cluster " << currentDirCluster << ")...\n";

        // Gọi hàm thông minh có logic xử lý xung đột (Collision Detection)
        vector<DeletedFileInfo> report = tool.analyzeRecoveryCandidates(currentDirCluster);

        if (report.empty()) {
            cout << "No deleted files found in Root Directory.\n";
            return 0;
        }

        // 5. HIỂN THỊ BÁO CÁO (Report Phase)
        cout << string(100, '-') << endl;
        cout << left << setw(5) << "ID" 
             << setw(15) << "Name" 
             << setw(10) << "Type" 
             << setw(10) << "Size" 
             << setw(22) << "Last Write" 
             << setw(15) << "Status" 
             << "Reason" << endl;
        cout << string(100, '-') << endl;

        for (const auto& file : report) {
            string type = file.isDir ? "<DIR>" : "FILE";
            string status = file.isRecoverable ? "GOOD" : "LOST";
            
            // Tách Time/Date từ timestamp gộp (nếu muốn in đẹp)
            uint32_t rawTime = file.lastWriteTime;
            
            cout << left << setw(5) << file.entryIndex 
                 << setw(15) << file.name 
                 << setw(10) << type 
                 << setw(10) << file.size 
                 << setw(22) << rawTime // Hoặc dùng formatTimestamp nếu tách ra
                 << setw(15) << status 
                 << file.statusReason << endl;
        }
        cout << string(100, '-') << endl;

        // 6. TƯƠNG TÁC NGƯỜI DÙNG & KHÔI PHỤC (Action Phase)
        int targetIndex;
        cout << "\nEnter the Entry ID to restore (or -1 to exit): ";
        cin >> targetIndex;

        if (targetIndex == -1) return 0;

        // Tìm thông tin file trong danh sách báo cáo
        bool found = false;
        bool isDir = false;
        for (const auto& f : report) {
            if (f.entryIndex == targetIndex) {
                found = true;
                isDir = f.isDir;
                if (!f.isRecoverable) {
                    cout << "[WARNING] This file is marked as LOST/COLLISION. Restore may result in corrupted data.\n";
                    cout << "Continue anyway? (y/n): ";
                    char ans; cin >> ans;
                    if (ans != 'y' && ans != 'Y') return 0;
                }
                break;
            }
        }

        if (!found) {
            cout << "Invalid ID.\n";
            return 0;
        }

        // 7. THỰC THI KHÔI PHỤC (Execution)
        if (isDir) {
            // Nếu là Folder -> Gọi khôi phục đệ quy (Recursive)
            // Nó sẽ cứu folder cha, sau đó tự động chui vào cứu các con
            tool.restoreTree(currentDirCluster, targetIndex);
        } else {
            // Nếu là File -> Gọi khôi phục đơn lẻ (In-Place)
            // 'R' là ký tự giả định thay thế cho dấu ? đầu tiên
            tool.restoreDeletedFile(currentDirCluster, targetIndex, 'R');
        }

    } catch (const exception& e) {
        cerr << "\n[CRITICAL ERROR] " << e.what() << endl;
        return 1;
    }

    return 0;
}