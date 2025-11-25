#include "FAT32.h"

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <array>

// ======================================================================
//                           DIR ENTRY METHODS
// ======================================================================
bool DirEntry::isDeleted() const
{
    return name[0] == 0xE5;
}

bool DirEntry::isLFN() const
{
    return (attr & 0x0F) == 0x0F;
}

bool DirEntry::isdDir() const
{
    return (attr & 0x10) != 0;
}

uint32_t DirEntry::getStartCluster() const
{
    uint32_t high = uint32_t(firstClusterHigh);
    uint32_t low = uint32_t(firstClusterLow);
    return (high << 16) | low;
}

// ======================================================================
//                        CONSTRUCTOR / DESTRUCTOR
// ======================================================================
FAT32Recovery::FAT32Recovery(const string &path) : imagePath(path)
{
    // fd = -1;
    bootSector.bytesPerSector = 0;
    bootSector.sectorsPerCluster = 0;
    bootSector.reservedSectors = 0;
    bootSector.numFATs = 0;
    bootSector.sectorsPerFat = 0;
    bootSector.rootCluster = 0;

    fatBegin = 0;
    dataBegin = 0;
    totalClusters = 0;

    vhd.open(path, ios::in | ios::out | ios::binary);

    if (!vhd.is_open())
        throw runtime_error(string("Open failed: ") + strerror(errno));

    // readBootSector();
    // loadFAT();
    // readMBR();
}

FAT32Recovery::~FAT32Recovery()
{
    if (vhd.is_open())
        vhd.close();
}

// ======================================================================
//                             LOW-LEVEL IO
// ======================================================================
string FAT32Recovery::formatShortName(const uint8_t name[11])
{
    string res;

    // name part
    for (int i = 0; i < 8; ++i)
    {
        if (name[i] == ' ')
            break;
        res.push_back(char(name[i]));
    }

    // extension part
    string ext;
    for (int i = 8; i < 11; ++i)
    {
        if (name[i] == ' ')
            break;
        ext.push_back(name[i]);
    }

    if (!ext.empty())
        res += "." + ext;

    return res;
}

ssize_t FAT32Recovery::readBytes(uint64_t offset, void *buf, size_t size) const
{
    // fstream::seekg yêu cầu quyền thay đổi trạng thái stream,
    // nên ta cần 'mutable' hoặc cast 'const' đi nếu vhd là const member.
    // Cách tốt nhất là dùng một biến fstream không const.

    auto &mutable_vhd = const_cast<fstream &>(vhd);

    mutable_vhd.clear(); // Xóa cờ lỗi (EOF, Fail) trước khi seek
    mutable_vhd.seekg(offset, ios::beg);

    if (mutable_vhd.fail())
        return -1;

    mutable_vhd.read((char *)buf, size);
    return mutable_vhd.gcount(); // Trả về số byte thực tế đã đọc
}

void FAT32Recovery::writeAll(ostream &out, const void *buf, size_t size) const
{
    // Ép kiểu về const char* vì fstream yêu cầu char*
    out.write(static_cast<const char *>(buf), size);

    // Kiểm tra trạng thái stream sau khi ghi
    if (out.fail() || out.bad())
    {
        // Có thể throw exception hoặc xử lý tùy logic của bạn
        throw runtime_error("Failed to write data to output file.");
    }
}
// ======================================================================
//                       MBR PARSING / VALIDATION
// ======================================================================
void FAT32Recovery::readMBR()
{
    cout << "[SCAN] Reading MBR(Master Boot Record)\n";
    ssize_t bytesRead = readBytes(0, &mbr, sizeof(MBR));
    if (bytesRead != sizeof(MBR))
    {
        throw runtime_error("Failed to read full MBR (512 bytes)");
    }

    // Check signature
    if (mbr.signature != 0xAA55)
        cout << "[MBR] No signature found\n";

    cout << "[SUCCESS] MBR loaded\n";
    cout << "[INFO] Starting validate and fix partition...\n";
    for (int i = 0; i < 4; ++i)
    {
        cout << "       Checking partition " << i << "...\n";
        validateAndFixPartition(i);
    }

    cout << "================================\n";
}

bool FAT32Recovery::validateAndFixPartition(int index)
{
    // Kiểm tra biên
    if (index < 0 || index >= 4)
        throw runtime_error("Invalid partition index");

    ParEntry &p = mbr.partitions[index];
    bool isMBRDirty = false; // Cờ đánh dấu xem MBR có bị thay đổi cần ghi lại không

    // 1. Check signature của MBR
    if (mbr.signature != 0xAA55)
    {
        cout << "[WARN] Invalid MBR signature (found " << hex << mbr.signature << "), fixing to 0xAA55...\n";
        mbr.signature = 0xAA55;
        isMBRDirty = true;
    }

    // 2. Must have non-zero LBA (Partition rỗng hoặc chưa khởi tạo)
    if (p.lbaFirst == 0)
    {
        cout << "[ERROR] Partition LBA=0 -> cannot fix (likely empty entry)\n";
        return false;
    }

    // 3. Read boot sector
    // Boot Sector nằm tại sector đầu tiên của Partition (LBA First)
    uint8_t sector[512];
    ssize_t n = readBytes((uint64_t)p.lbaFirst * 512ULL, sector, 512);
    if (n != 512)
    {
        cout << "[ERROR] Cannot read boot sector at LBA " << p.lbaFirst << "\n";
        return false;
    }

    // 4. Validate Boot Sector Signature (0xAA55 tại offset 510)
    // uint16_t bsSignature = read_u16_le(sector + 510);
    // if (bsSignature != 0xAA55)
    // {
    //     cout << "[ERR] Invalid Boot Sector Signature at LBA " << p.lbaFirst
    //               << ". Found: 0x" << hex << bsSignature << " (Expected: 0xAA55)\n";
    //     return false;
    // }

    // Cast buffer -> struct BootSector
    BootSector *bpb = reinterpret_cast<BootSector *>(sector);

    // 5. Validate BPB logic
    if (bpb->bytesPerSector != 512 ||
        bpb->sectorsPerCluster == 0 ||
        bpb->totalSectors32 == 0)
    {
        cout << "[ERROR] Invalid FAT32 Boot Sector values -> partition description is wrong\n";
        return false;
    }

    uint32_t correctSize = bpb->totalSectors32;

    // 6. Fix partition type
    // FAT32 LBA thường là 0x0C. Nếu nó đang sai (ví dụ 0x00 hoặc loại khác), ta sửa lại.
    if (p.partitionType != 0x0B && p.partitionType != 0x0C)
    {
        cout << "[FIX] Wrong partition type 0x" << std::hex << (int)p.partitionType
             << " -> setting to FAT32 LBA (0x0C)\n";
        p.partitionType = 0x0C;
        isMBRDirty = true;
    }

    // 7. Fix size mismatch
    // Nếu kích thước trong Partition Table khác với kích thước khai báo trong Boot Sector
    if (p.numSectors != correctSize)
    {
        std::cout << "[FIX] Wrong partition size: "
                  << std::dec << p.numSectors << " -> " << correctSize << "\n";
        p.numSectors = correctSize;
        isMBRDirty = true;
    }

    // 8. Ghi đè MBR xuống đĩa nếu có sửa đổi (Write Back)
    if (isMBRDirty)
    {
        // Xóa các cờ lỗi (nếu có) của fstream
        vhd.clear();
        // Di chuyển con trỏ ghi về đầu file (MBR nằm ở LBA 0, offset 0)
        vhd.seekp(0, std::ios::beg);
        if (!vhd.fail())
        {
            vhd.write(reinterpret_cast<const char *>(&mbr), sizeof(MBR));
            vhd.flush();
            std::cout << "[INFO] MBR has been updated and saved to disk.\n";
        }
        else
        {
            std::cout << "[ERROR] Failed to seek to MBR position for writing.\n";
            return false;
        }
    }

    // (Optional) Fix CHS
    // memset(p.chsFirst, 0, 3);
    // memset(p.chsLast, 0, 3);

    return true;
}

// // ======================================================================
// //                       BOOT SECTOR PARSING / VALIDATION
// // ======================================================================
void FAT32Recovery::listPartition()
{
    cout << "=== Partition Table ===\n";
    for (int i = 0; i < 4; i++)
    {
        ParEntry &p = mbr.partitions[i];
        // Bỏ qua partition rỗng
        if (p.numSectors == 0 || p.lbaFirst == 0)
            continue;

        cout << "Partition [" << i << "]: "
             << "Type=0x" << hex << (int)p.partitionType << dec
             << ", Start LBA=" << p.lbaFirst
             << ", Size=" << p.numSectors << " sectors";

        if (p.partitionType == 0x0B || p.partitionType == 0x0C)
            cout << " (FAT32 Detected)";
        else if (p.partitionType == 0x07)
            cout << " (NTFS/exFAT)";
        else
            cout << " (Unknown)";

        cout << "\n";
    }
    cout << "================================\n";
}

bool FAT32Recovery::parseAndValidateBootSector(const uint8_t *buffer)
{
    // 1. Check signature ở cuối sector (Offset 510)
    uint16_t signature = read_u16_le(buffer + 510);
    if (signature != 0xAA55)
        return false;

    const BootSector *tempBS = reinterpret_cast<const BootSector *>(buffer);

    // 2. Validate Bytes Per Sector
    // FAT32 chuẩn thường là 512, 1024, 2048, 4096.
    if (tempBS->bytesPerSector == 0 ||
        (tempBS->bytesPerSector != 512 && tempBS->bytesPerSector != 1024 && tempBS->bytesPerSector != 2048 && tempBS->bytesPerSector != 4096))
        return false;

    // 3. Validate Sectors Per Cluster
    // Phải là lũy thừa của 2 và <= 128
    if (tempBS->sectorsPerCluster == 0 ||
        tempBS->sectorsPerCluster > 128 ||
        (tempBS->sectorsPerCluster & (tempBS->sectorsPerCluster - 1)) != 0)
        return false;

    // 4. Validate Reserved Sectors (Phải > 0, thường là 32 với FAT32)
    if (tempBS->reservedSectors < 1)
        return false;

    // 5. Validate Number of FATs (Thường là 2, đôi khi là 1)
    if (tempBS->numFATs < 1 || tempBS->numFATs > 2)
        return false;

    // 6. Validate Sectors Per FAT (FAT32 dùng field 32-bit tại offset 0x24)
    if (tempBS->sectorsPerFat == 0)
        return false;

    // 7. Validate Root Cluster (Thường là 2)
    if (tempBS->rootCluster < 2)
        return false;

    // 8. Validate Total Sectors (Phải khác 0)
    if (tempBS->totalSectors32 == 0)
        return false;

    // === Hợp lệ: Copy dữ liệu vào biến thành viên của class ===
    // Copy phần struct (64 bytes)
    memcpy(&this->bootSector, buffer, sizeof(BootSector));

    return true;
}

void FAT32Recovery::readBootSector(int partitionId)
{
    cout << "[SCAN] Reading Boot Secotr at partition " << partitionId << "...\n";
    // 1. Check validation of Index
    if (partitionId < 0 || partitionId >= 4)
        throw runtime_error("Invalid partition index. Must be 0-3.");

    ParEntry &p = mbr.partitions[partitionId];

    // 2. Check if partition exist
    if (p.lbaFirst == 0 || p.numSectors == 0)
    {
        throw runtime_error("Partition is empty or invalid.");
    }

    // 3. Check Partition type (FAT32)
    if (p.partitionType != 0x0B && p.partitionType != 0x0C)
    {
        cout << "[WARN] Partition type is not standard FAT32 (0x0B/0x0C). Reading anyway...\n";
    }

    // 4. Calculate start Offset (locate Boot Sector)
    uint64_t partitionStartOffset = (uint64_t)p.lbaFirst * 512ULL;
    cout << "[SCAN] Reading Boot Sector for Partition " << partitionId
         << " at Offset " << partitionStartOffset << "\n";

    // 5. Read và Validate
    uint8_t bsBuffer[512];
    bool valid = false;

    // --- Try Main Boot Sector ---
    if (readBytes(partitionStartOffset, bsBuffer, 512) == 512)
    {
        if (parseAndValidateBootSector(bsBuffer))
        {
            cout << "[INFO] Main Boot Sector OK.\n";
            valid = true;
        }
    }

    // --- Try Backup Boot Sector ---
    // Backup thường nằm ở Sector 6 so với đầu Partition
    if (!valid)
    {
        cout << "[WARN] Main BS failed. Trying Backup at Sector 6...\n";
        uint64_t backupOffset = partitionStartOffset + (6ULL * 512ULL);

        if (readBytes(backupOffset, bsBuffer, 512) == 512)
        {
            if (parseAndValidateBootSector(bsBuffer))
            {
                cout << "[INFO] Backup Boot Sector OK.\n";
                valid = true;

                if (!fixBootSectorBackup(partitionStartOffset))
                {
                    cout << "[WARN] Failed to automatically fix Main Boot Sector.\n";
                }
            }
        }
    }

    if (!valid)
        throw runtime_error("Cannot load Boot Sector for the selected partition.");

    // 6. Calculate FAT/Data (Base on Partition Offset)
    fatBegin = partitionStartOffset + (uint64_t)bootSector.reservedSectors * bootSector.bytesPerSector;

    uint64_t fatSizeInBytes = (uint64_t)bootSector.sectorsPerFat * bootSector.bytesPerSector;
    dataBegin = fatBegin + ((uint64_t)bootSector.numFATs * fatSizeInBytes);

    // Tính Total Clusters
    uint64_t dataSectors = bootSector.totalSectors32 - bootSector.reservedSectors - (bootSector.numFATs * bootSector.sectorsPerFat);
    totalClusters = dataSectors / bootSector.sectorsPerCluster;

    cout << "[SUCCESS] Initialized Volume from Partition " << partitionId << "\n";
    cout << "================================\n";
}

bool FAT32Recovery::fixBootSectorBackup(uint64_t partitionStartOffset)
{
    uint8_t backupBS[512];
    for (int i = 0; i < 4; i++)
    {
        if (mbr.partitions[i].partitionType == 0x0B || mbr.partitions[i].partitionType == 0x0C)
        {
            partitionStartOffset = (uint64_t)mbr.partitions[i].lbaFirst * 512ULL;
            break;
        }
    }

    uint64_t backupOffset = partitionStartOffset + (6ULL * 512ULL); // Sector 6
    uint64_t mainOffset = partitionStartOffset;                     // Sector 0

    // 1. Đọc Backup Boot Sector
    if (readBytes(backupOffset, backupBS, 512) != 512)
    {
        cout << "[ERROR] Failed to read Backup Boot Sector for fixing.\n";
        return false;
    }

    // 2. Validate lại cho chắc
    // Lưu ý: parseAndValidateBootSector sẽ thay đổi this->bootSector,
    // nhưng ở đây ta chỉ muốn check bool return thôi.
    // Để an toàn, ta copy BootSector hiện tại ra biến tạm hoặc chấp nhận nó cập nhật lại.
    BootSector savedState = this->bootSector;
    if (!parseAndValidateBootSector(backupBS))
    {
        cout << "[ERROR] Backup Boot Sector is also invalid. Cannot fix.\n";
        this->bootSector = savedState; // Restore state
        return false;
    }

    // 3. Ghi đè lên Main Boot Sector (Sector 0)
    cout << "[INFO] Overwriting Main Boot Sector with Backup...\n";

    vhd.clear();
    vhd.seekp(mainOffset, std::ios::beg);
    if (vhd.fail())
    {
        cout << "[ERROR] Seek failed.\n";
        return false;
    }

    vhd.write(reinterpret_cast<const char *>(backupBS), 512);
    if (vhd.fail())
    {
        cout << "[ERROR] Write failed.\n";
        return false;
    }

    vhd.flush();
    cout << "[INFO] Successfully fixed Boot Sector.\n";
    return true;
}

void FAT32Recovery::loadFAT()
{
    // Đảm bảo các thông số đã được khởi tạo từ readBootSector/selectPartition
    if (bootSector.sectorsPerFat == 0 || bootSector.bytesPerSector == 0 || fatBegin == 0)
    {
        throw runtime_error("FAT parameters not initialized. Call readBootSector/selectPartition first.");
    }

    // 1. Tính toán kích thước của một bản sao FAT (bằng byte)
    uint64_t fatSizeBytes = (uint64_t)bootSector.sectorsPerFat * bootSector.bytesPerSector;

    if (fatSizeBytes == 0)
    {
        throw runtime_error("Calculated FAT size is zero.");
    }

    cout << "[INFO] FAT table size: " << fatSizeBytes << " bytes. Reading from offset: "
         << fatBegin << endl;

    // 2. Chuẩn bị buffer và đọc toàn bộ FAT table từ đĩa
    std::vector<uint8_t> fatBuffer(fatSizeBytes);

    ssize_t n = readBytes(fatBegin, fatBuffer.data(), fatSizeBytes);

    if (n != (ssize_t)fatSizeBytes)
    {
        // Xử lý lỗi đọc
        throw runtime_error("Failed to read entire FAT table from disk. Read " +
                            std::to_string(n) + " of " + std::to_string(fatSizeBytes) + " bytes.");
    }

    // 3. Xử lý các FAT entry
    // Mỗi entry FAT32 là 4 bytes.
    uint32_t numEntries = fatSizeBytes / sizeof(uint32_t);
    FAT.reserve(numEntries); // Đặt trước kích thước để tối ưu hiệu suất

    for (uint32_t i = 0; i < numEntries; ++i)
    {
        // Con trỏ tới vị trí 4-byte của entry hiện tại
        const uint8_t *entryPtr = fatBuffer.data() + i * sizeof(uint32_t);

        // Đọc giá trị 32-bit (4 bytes) theo kiểu Little Endian
        uint32_t entry = read_u32_le(entryPtr);

        // *Chú ý quan trọng:* FAT32 chỉ sử dụng 28 bit thấp (0x0FFFFFFF).
        // 4 bit cao nhất (MSBs) phải được che đi (masked out) vì chúng thường được dùng làm bit lỗi hoặc reserved.
        FAT.push_back(entry & 0x0FFFFFFF);
    }

    cout << "[INFO] Loaded FAT table successfully. Total entries (clusters): " << std::dec << FAT.size() << endl;
    cout << "       FAT[0] (Media Type): 0x" << std::hex << FAT[0] << endl;
    cout << "       FAT[1] (EOC Marker): 0x" << std::hex << FAT[1] << std::dec << endl;

    // Dọn dẹp: Đảm bảo luồng cout không bị ảnh hưởng bởi hex/dec
    cout << dec;
    cout << "================================\n";
}

// ======================================================================
//                       FILE SYSTEM (FAT32)
// ======================================================================

// ======================================================================
//                       DELETED FILE RECOVERY
// ======================================================================
string FAT32Recovery::restoreDeletedName(const uint8_t name[11])
{
    uint8_t tempName[11];
    memcpy(tempName, name, 11);
    if (tempName[0] == 0xE5)
        tempName[0] = '_';
    return formatShortName(tempName);
}

void FAT32Recovery::rawRecoverFile(uint32_t startCluster, uint32_t fileSize, const string &destPath)
{
    cout << "   -> Recovering: Start Cluster " << startCluster << ", Size " << fileSize << " bytes...\n";

    // 1. Mở file đầu ra bằng ofstream (C++)
    ofstream outFile(destPath, ios::binary | ios::trunc);
    if (!outFile.is_open())
    {
        cout << "      [ERROR] Cannot create output file: " << destPath << "\n";
        return;
    }

    uint32_t currentCluster = startCluster;
    uint32_t bytesRemaining = fileSize;
    uint32_t bytesPerClus = bootSector.sectorsPerCluster * bootSector.bytesPerSector;
    vector<uint8_t> buffer;

    while (bytesRemaining > 0)
    {
        // Kiểm tra an toàn: Tràn dải cluster
        if (currentCluster >= totalClusters + 2)
        {
            cout << "      [WARN] Reached end of valid clusters.\n";
            break;
        }

        // --- Logic: Consecutive Empty Cluster ---
        // Nếu là cluster đầu tiên HOẶC cluster hiện tại trong FAT = 0 (trống)
        bool isStart = (currentCluster == startCluster);
        bool isFree = (currentCluster < FAT.size() && FAT[currentCluster] == 0);

        if (isStart || isFree)
        {
            try
            {
                // Đọc data từ Disk Image
                readCluster(currentCluster, buffer);

                // Tính toán lượng byte cần ghi
                size_t chunkSize = (bytesRemaining < bytesPerClus) ? bytesRemaining : bytesPerClus;

                // Ghi ra file kết quả
                outFile.write((char *)buffer.data(), chunkSize);

                bytesRemaining -= chunkSize;
            }
            catch (exception &e)
            {
                cout << "      [ERROR] Reading cluster " << currentCluster << ": " << e.what() << "\n";
                break;
            }
        }
        else
        {
            // Nếu cluster này đã bị chiếm dụng (Allocated) bởi file khác -> Bỏ qua (Skip)
            // cout << "      [Debug] Skipping allocated cluster " << currentCluste\nr;
        }

        // Tăng tuyến tính để tìm mảnh tiếp theo
        currentCluster++;
    }

    outFile.close();
    cout << "      [INFO] Saved to " << destPath << "\n";
}

void FAT32Recovery::recoverDeletedFilesInDir(uint32_t dirCluster, const string &outputFolder)
{
    // Tạo folder (Lệnh này phụ thuộc OS, trên Windows dùng mkdir)
    string cmd = "mkdir \"" + outputFolder + "\"";
    system(cmd.c_str());

    cout << "[INFO] Scanning deleted files in Cluster " << dirCluster << "\n";

    vector<uint32_t> dirChain = followFAT(dirCluster);
    if (dirChain.empty())
        dirChain.push_back(dirCluster);

    vector<uint8_t> buf;
    for (uint32_t c : dirChain)
    {
        readCluster(c, buf);
        for (size_t off = 0; off + 32 <= buf.size(); off += 32)
        {
            DirEntry de;
            memcpy(&de, buf.data() + off, 32);

            if (de.name[0] == 0x00)
                break; // Hết thư mục

            // Logic nhận diện file xóa: Bắt đầu 0xE5 và không phải LFN
            if (de.name[0] == 0xE5 && !de.isLFN())
            {
                string recName = restoreDeletedName(de.name);
                uint32_t startClus = de.getStartCluster();
                uint32_t fSize = de.fileSize;

                // Basic validation để lọc rác
                if (startClus >= 2 && fSize > 0 && fSize < 200 * 1024 * 1024)
                {
                    cout << "Found: " << recName << " (Start: " << startClus << ", Size: " << fSize << ")\n";
                    string outPath = outputFolder + "/" + recName;
                    rawRecoverFile(startClus, fSize, outPath);
                }
            }
        }
    }
}

void FAT32Recovery::recoverAllRecursively(uint32_t cluster, const string &hostPath)
{
    // 1. Tạo thư mục trên máy tính (Host OS) để giữ đúng cấu trúc cây
    // (Lưu ý: trên Windows dùng lệnh mkdir string, Linux dùng mkdir -p)
    string cmd = "mkdir -p \"" + hostPath + "\""; // Linux/MacOS
    // string cmd = "mkdir \"" + hostPath + "\""; // Windows (bạn tự điều chỉnh tùy OS)
    system(cmd.c_str());

    cout << "[SCAN] Entering Directory Cluster: " << cluster << " -> " << hostPath << "\n";

    // 2. Lấy nội dung thư mục (Directory Content)
    vector<uint32_t> dirChain = followFAT(cluster);
    if (dirChain.empty())
        dirChain.push_back(cluster); // Fallback nếu FAT lỗi

    vector<uint8_t> buf;
    for (uint32_t c : dirChain)
    {
        // Đọc dữ liệu của cluster hiện tại trong chuỗi thư mục
        try
        {
            readCluster(c, buf);
        }
        catch (...)
        {
            continue;
        } // Bỏ qua nếu lỗi đọc đĩa

        // Duyệt từng entry 32-byte
        for (size_t off = 0; off + 32 <= buf.size(); off += 32)
        {
            DirEntry de;
            memcpy(&de, buf.data() + off, 32);

            if (de.name[0] == 0x00)
                break; // Hết danh sách -> Dừng xử lý cluster này
            if (de.isLFN())
                continue; // Bỏ qua Long File Name entry

            // Lấy tên (Short Name)
            string name = formatShortName(de.name);

            // ==========================================
            // CASE 1: FILE ĐÃ XÓA (Byte đầu là 0xE5)
            // ==========================================
            if (de.isDeleted())
            {
                // Chỉ phục hồi nếu nó KHÔNG phải là thư mục (Directory) đã xóa
                // (Khôi phục thư mục đã xóa rất khó vì mất link, ở đây ta chỉ cứu FILE)
                if (!de.isdDir())
                {
                    string recName = restoreDeletedName(de.name);
                    uint32_t startClus = de.getStartCluster();
                    uint32_t size = de.fileSize;

                    // Validate cơ bản
                    if (startClus >= 2 && size > 0 && size < 500 * 1024 * 1024)
                    {
                        string fullOutputPath = hostPath + "/" + recName;
                        // Gọi hàm rawRecoverFile bạn đã viết trước đó
                        rawRecoverFile(startClus, size, fullOutputPath);
                    }
                }
            }
            // ==========================================
            // CASE 2: THƯ MỤC ĐANG TỒN TẠI (Đệ quy)
            // ==========================================
            else if (de.isdDir())
            {
                // RẤT QUAN TRỌNG: Bỏ qua "." và ".." để tránh lặp vô tận
                if (name == "." || name == "..")
                    continue;

                uint32_t subDirCluster = de.getStartCluster();

                // Validate cluster hợp lệ
                if (subDirCluster >= 2)
                {
                    string newHostPath = hostPath + "/" + name;

                    // GỌI ĐỆ QUY: Đi sâu vào thư mục con
                    recoverAllRecursively(subDirCluster, newHostPath);
                }
            }
        }
    }
}
// ======================================================================
//                       Scanning & recovery routines
// ======================================================================
vector<uint32_t> FAT32Recovery::followFAT(uint32_t startCluster) const
{
    vector<uint32_t> chain;

    // Sử dụng Set để phát hiện vòng lặp vô tận (Infinite Loop)
    // Trường hợp FAT bị lỗi: 5 -> 6 -> 7 -> 5 ...
    set<uint32_t> visited;

    uint32_t current = startCluster;

    // FAT32 Mask: Chỉ dùng 28 bit thấp, 4 bit cao là reserved.
    const uint32_t FAT32_MASK = 0x0FFFFFFF;
    const uint32_t EOC_MARK = 0x0FFFFFF8; // Giá trị >= mức này là kết thúc
    const uint32_t BAD_CLUS = 0x0FFFFFF7; // Cluster hỏng

    while (true)
    {
        // 1. Kiểm tra biên (Boundary Check)
        // Cluster hợp lệ phải >= 2 và nằm trong kích thước bảng FAT
        if (current < 2 || current >= FAT.size())
        {
            // Nếu trỏ ra ngoài phạm vi -> Chuỗi bị đứt hoặc lỗi
            break;
        }

        // 2. Kiểm tra vòng lặp (Loop Detection)
        if (visited.count(current))
        {
            cout << "[Warning] FAT Cycle detected at cluster " << current << ". Stopping chain.\n";
            break;
        }

        // Ghi nhận cluster này
        visited.insert(current);
        chain.push_back(current);

        // 3. Đọc giá trị tiếp theo từ bảng FAT
        // Lưu ý: Phải dùng bitwise AND với 0x0FFFFFFF
        uint32_t next = FAT[current] & FAT32_MASK;

        // 4. Các điều kiện dừng (Termination Conditions)

        // A. End of Chain (EOC): Kết thúc file
        if (next >= EOC_MARK)
        {
            break;
        }

        // B. Bad Cluster: Cluster bị đánh dấu hỏng
        if (next == BAD_CLUS)
        {
            cout << "[Warning] Encountered BAD CLUSTER marker.\n";
            break;
        }

        // C. Free Cluster (0): Chuỗi bị đứt gãy
        // (Bình thường file đang tồn tại không được trỏ về 0, nếu có là do lỗi cấu trúc)
        if (next == 0)
        {
            // cout << "[Warning] Chain broken (points to FREE) at " << curren\nt;
            break;
        }

        // 5. Nhảy tới cluster tiếp theo
        current = next;
    }

    return chain;
}

// ======================================================================
//                       UTILS
// ======================================================================
void FAT32Recovery::readCluster(uint32_t cluster, vector<uint8_t> &buffer) const
{
    // 1. Kiểm tra tính hợp lệ
    // Cluster trong FAT32 bắt đầu từ 2. Các giá trị 0 và 1 được dành riêng.
    if (cluster < 2)
    {
        // Có thể throw lỗi hoặc return rỗng tùy chiến lược xử lý lỗi
        throw runtime_error("Invalid cluster number: " + to_string(cluster));
    }

    // 2. Tính toán Offset (Vị trí byte trên đĩa)
    // Công thức: Offset = Start_Data_Region + (Cluster_Index - 2) * Cluster_Size
    uint32_t clusterSize = bootSector.sectorsPerCluster * bootSector.bytesPerSector;

    // Cần ép kiểu uint64_t để tránh tràn số (overflow) với ổ đĩa lớn
    uint64_t offset = dataBegin + (uint64_t)(cluster - 2) * clusterSize;

    // 3. Chuẩn bị Buffer
    // Resize buffer đúng bằng kích thước 1 cluster để chứa dữ liệu
    buffer.resize(clusterSize);

    // 4. Đọc dữ liệu
    // Gọi hàm readBytes (đã viết lại dùng fstream)
    ssize_t bytesRead = readBytes(offset, buffer.data(), clusterSize);

    // 5. Kiểm tra lỗi đọc
    if (bytesRead != (ssize_t)clusterSize)
    {
        throw runtime_error("Failed to read cluster " + to_string(cluster));
    }
}