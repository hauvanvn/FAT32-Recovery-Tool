#include "FAT32.h"

#include <fcntl.h>

#include <sys/stat.h>
#include <sys/types.h>

#include <stdexcept>
#include <cstring>
#include <cerrno>
#include <algorithm>
#include <array>
#include <map>

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

// Helper: trim trailing spaces from a string
static inline void trimRight(string &s)
{
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
}

string DirEntry::getNameString() const
{
    // Handle deleted / empty
    if (name[0] == 0x00)
        return string();
    if (name[0] == 0xE5)
    {
        // deleted marker (0xE5) — show something helpful
        string tmp = "?";
        tmp += " (deleted)";
        return tmp;
    }

    // Build name part (first 8 bytes)
    string base;
    base.reserve(8);
    for (int i = 0; i < 8; ++i)
    {
        char c = static_cast<char>(name[i]);
        base.push_back(c);
    }
    trimRight(base);

    // Build ext part (last 3 bytes)
    string ext;
    ext.reserve(3);
    for (int i = 8; i < 11; ++i)
    {
        char c = static_cast<char>(name[i]);
        ext.push_back(c);
    }
    trimRight(ext);

    // If name is special (first byte 0x05 means 0xE5 in OEM) handle it:
    if (static_cast<uint8_t>(name[0]) == 0x05)
    {
        // 0x05 in first byte represents 0xE5 in actual name in some OEM encodings
        if (!base.empty() && base[0] == '\x05')
            base[0] = '\xE5';
    }

    // Combine
    if (!ext.empty())
    {
        return base + "." + ext;
    }
    else
    {
        return base;
    }
}

uint32_t DirEntry::getWriteTimestamp() const
{
    return (uint32_t(date) << 16) | uint32_t(time);
}

uint32_t DirEntry::getCreationTimestamp() const
{
    return (uint32_t(crtDate) << 16) | uint32_t(crtTime);
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

    bool needRebuild = false;

    // Check signature
    if (mbr.signature != 0xAA55)
    {
        cout << "[WARN] Invalid MBR signature (found 0x" << hex << mbr.signature << "), expected 0xAA55\n";
        needRebuild = true;
    }
    else
    {
        int validPartitionsCount = 0;
        int nonEmptyEntries = 0;

        for (int i = 0; i < 4; ++i)
        {
            ParEntry &p = mbr.partitions[i];
            if (p.lbaFirst == 0 && p.numSectors == 0)
                continue; // Empty partition entry
            nonEmptyEntries++;

            uint8_t checkBuf[512];
            uint64_t offset = (uint64_t)p.lbaFirst * 512ULL;

            if (readBytes(offset, checkBuf, 512) == 512)
            {
                if (parseAndValidateBootSector(checkBuf))
                {
                    validPartitionsCount++;
                }
                else
                {
                    cout << "[WARN] Partition " << i << " has invalid Boot Sector data.\n";
                }
            }
        }

        if (nonEmptyEntries == 0)
        {
            cout << "[WARN] No valid partitions found in MBR.\n";
            needRebuild = true;
        }
        else if (validPartitionsCount == 0)
        {
            cout << "[WARN] No valid FAT32 partitions found in MBR.\n";
            needRebuild = true;
        }
    }

    if (needRebuild)
    {
        cout << "[CRITICAL] MBR appears to be corrupted. Initiating rebuild process...\n";
        scanAndRebuildMBR();
    }
    else
    {
        cout << "[SUCCESS] MBR loaded\n";
        cout << "[INFO] Starting validate and fix partition...\n";
        for (int i = 0; i < 4; ++i)
        {
            cout << "       Checking partition " << i << "...\n";
            validateAndFixPartition(i);
        }
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
    bool dirtyBoot = false;

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
        cout << "[WARN] Partition empty\n";
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

    // 4. Validate Boot Sector Signature(0xAA55 tại offset 510)
    uint16_t bsSignature = read_u16_le(sector + 510);
    if (bsSignature != 0xAA55)
    {
        cout << "[ERR] Invalid Boot Sector Signature at LBA " << p.lbaFirst
             << ". Found: 0x" << hex << bsSignature << " (Expected: 0xAA55)\n";

        sector[510] = 0x55;
        sector[511] = 0xAA;
        dirtyBoot = true;
    }

    // Cast buffer -> struct BootSector
    BootSector *bpb = reinterpret_cast<BootSector *>(sector);

    // 5. Validate BPB logic
    bool BS_corrupted = false;

    if (bpb->bytesPerSector != 512)
    {
        cout << "[FIX] bytesPerSector wrong (" << dec << bpb->bytesPerSector
             << ") -> 512\n";
        bpb->bytesPerSector = 512;
        dirtyBoot = true;
    }

    if (bpb->sectorsPerCluster == 0)
    {
        cout << "[FIX] sectorsPerCluster was 0 -> setting safe default (8)\n";
        bpb->sectorsPerCluster = 8;
        dirtyBoot = true;
    }

    if (bpb->reservedSectors == 0)
    {
        cout << "[FIX] reservedSectors was 0 -> 32\n";
        bpb->reservedSectors = 32;
        dirtyBoot = true;
    }

    if (bpb->numFATs != 2)
    {
        cout << "[FIX] numFATs wrong -> setting to 2\n";
        bpb->numFATs = 2;
        dirtyBoot = true;
    }

    // FAT32 must have fatSize32 != 0
    if (bpb->sectorsPerFat == 0)
    {
        cout << "[ERR] FAT32 but fatSize32 = 0 -> cannot auto-fix safely\n";
        BS_corrupted = true;
    }

    if (bpb->totalSectors32 == 0)
    {
        cout << "[ERR] totalSectors32 = 0 -> cannot recover\n";
        BS_corrupted = true;
    }

    if (BS_corrupted)
        return false;

    // 6. Fix partition type
    // FAT32 LBA thường là 0x0C. Nếu nó đang sai (ví dụ 0x00 hoặc loại khác), ta sửa lại.
    if (p.partitionType != 0x0B && p.partitionType != 0x0C)
    {
        cout << "[FIX] Wrong partition type 0x" << hex << (int)p.partitionType
             << " -> setting to FAT32 LBA (0x0C)\n";
        p.partitionType = 0x0C;
        isMBRDirty = true;
    }

    // 7. Fix size mismatch
    // Nếu kích thước trong Partition Table khác với kích thước khai báo trong Boot Sector
    uint32_t fsTotals = bpb->totalSectors32;

    if (p.numSectors != fsTotals)
    {
        cout << "[FIX] Wrong partition size: "
             << dec << p.numSectors << " -> " << fsTotals << "\n";
        p.numSectors = fsTotals;
        isMBRDirty = true;
    }

    // 8. Invalid extended flags
    if ((bpb->extFlags & 0x0F) >= 2)
    {
        cout << "[FIX] extFlags FAT number invalid -> setting active FAT = 0\n";
        bpb->extFlags &= 0xFFF0; // clear lower 4 bits
        dirtyBoot = true;
    }

    // 9. Fix FSINFO sector if known default is broken
    if (bpb->fsInfo != 1)
    {
        cout << "[FIX] fsInfo wrong -> 1\n";
        bpb->fsInfo = 1;
        dirtyBoot = true;
    }

    if (bpb->bkBootSector != 6)
    {
        cout << "[FIX] bkBootSector wrong -> 6\n";
        bpb->bkBootSector = 6;
        dirtyBoot = true;
    }

    // 10. Ghi đè Boot Sector nếu có sửa đổi (Write Back)
    if (dirtyBoot)
    {
        cout << "[INFO] Writing repaired Boot Sector...\n";

        vhd.clear();
        vhd.seekp((uint64_t)p.lbaFirst * 512ULL);
        if (!vhd.fail())
        {
            vhd.write((char *)sector, 512);
            vhd.flush();
            cout << "[INFO] Boot Sector has been updated and saved to disk.\n";
        }
        else
        {
            cout << "[ERROR] Failed to seek to Boot Sector position for writing.\n";
            return false;
        }
    }

    // 10. Ghi đè MBR xuống đĩa nếu có sửa đổi (Write Back)
    if (isMBRDirty)
    {
        // Xóa các cờ lỗi (nếu có) của fstream
        vhd.clear();
        // Di chuyển con trỏ ghi về đầu file (MBR nằm ở LBA 0, offset 0)
        vhd.seekp(0, ios::beg);
        if (!vhd.fail())
        {
            vhd.write(reinterpret_cast<const char *>(&mbr), sizeof(MBR));
            vhd.flush();
            cout << "[INFO] MBR has been updated and saved to disk.\n";
        }
        else
        {
            cout << "[ERROR] Failed to seek to MBR position for writing.\n";
            return false;
        }
    }

    // (Optional) Fix CHS
    // memset(p.chsFirst, 0, 3);
    // memset(p.chsLast, 0, 3);

    return true;
}

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

void FAT32Recovery::scanAndRebuildMBR()
{
    cout << "[CRITICAL RECOVERY] Scanning disk for FAT32 partitions to rebuild MBR...\n";

    memset(mbr.partitions, 0, sizeof(mbr.partitions));
    mbr.signature = 0xAA55;
    int partFound = 0;

    uint8_t buf[512];
    uint64_t currentSector = 0;
    uint64_t maxSectors = 10000000; // Giới hạn quét (tùy chỉnh theo kích thước đĩa)

    while (currentSector < maxSectors && partFound < 4)
    {
        if (currentSector == 0)
        {
            currentSector = 63;
            continue; // Bỏ qua MBR
        }

        uint64_t offset = currentSector * 512ULL;
        if (readBytes(offset, buf, 512) != 512)
            break;

        if (parseAndValidateBootSector(buf))
        {
            uint32_t totalSectors = bootSector.totalSectors32;
            cout << "   -> Found FAT32 Boot Sector at LBA " << currentSector
                 << " (Size: " << totalSectors << " sectors)\n";
            // Điền thông tin vào partition entry
            ParEntry &p = mbr.partitions[partFound];
            p.status = (partFound == 0) ? 0x80 : 0x00; // Active cho partition đầu tiên
            p.partitionType = 0x0C;                    // FAT32 LBA
            p.lbaFirst = (uint32_t)currentSector;
            p.numSectors = totalSectors;

            partFound++;
            currentSector += p.numSectors; // Bỏ qua vùng partition này
            continue;
        }
        if (currentSector < 65536)
            currentSector++; // Quét chậm hơn ở vùng đầu
        else
            currentSector += 2048; // Quét nhanh hơn ở vùng sau
    }

    if (partFound > 0)
    {
        cout << "[SUCCESS] Found " << partFound << " FAT32 partition(s). Writing new MBR to disk...\n";
        // Ghi MBR mới xuống đĩa
        vhd.clear();
        vhd.seekp(0, ios::beg);
        vhd.write(reinterpret_cast<const char *>(&mbr), sizeof(MBR));
        vhd.flush();
        cout << "[INFO] New MBR has been written to disk.\n";
    }
    else
    {
        cout << "[FAILED] No FAT32 partitions found during scan. Cannot rebuild MBR.\n";
    }
}

// // ======================================================================
// //                       BOOT SECTOR PARSING / VALIDATION
// // ======================================================================
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
        uint16_t backupSectorLocation = 6;
        uint16_t possibleLocation = read_u16_le(bsBuffer + 50);

        if (possibleLocation > 0 && possibleLocation != 6 && possibleLocation < 64)
        {
            cout << "[INFO] Detected Backup Boot Sector location from BPB: Sector " << possibleLocation << "\n";
            backupSectorLocation = possibleLocation;
        }

        uint64_t backupOffset = partitionStartOffset + ((uint64_t)backupSectorLocation * 512ULL);

        if (readBytes(backupOffset, bsBuffer, 512) == 512)
        {
            if (parseAndValidateBootSector(bsBuffer))
            {
                cout << "[INFO] Backup Boot Sector OK.\n";

                if (fixBootSectorBackup(partitionStartOffset, backupSectorLocation))
                {
                    cout << "[SUCCESS] Boot Sector fixed from Backup.\n";
                    valid = true;
                }
                else
                {
                    cout << "[ERROR] Failed to fix Boot Sector from Backup.\n";
                }
            }
        }
        else
        {
            cout << "[ERROR] Cannot read Backup Boot Sector.\n";
        }
    }

    if (!valid)
    {
        cout << "[WARN] Both Boot Sectors are invalid. Attempting to reconstruct...\n";
        if (reconstructBootSector(partitionId))
        {
            cout << "[SUCCESS] Boot Sector reconstructed successfully.\n";
            valid = true;
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

bool FAT32Recovery::fixBootSectorBackup(uint64_t partitionStartOffset, uint16_t backupSectorLocation)
{
    if (partitionStartOffset == 0)
    {
        cout << "[ERROR] Invalid partition start offset.\n";
        return false;
    }

    uint8_t backupBS[512];
    uint64_t backupOffset = partitionStartOffset + ((uint64_t)backupSectorLocation * 512ULL);
    uint64_t mainOffset = partitionStartOffset;

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
    vhd.seekp(mainOffset, ios::beg);
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

bool FAT32Recovery::reconstructBootSector(int partitionID)
{
    cout << "\n[CRITICAL RECOVERY] Both Boot Sectors are dead. Attempting to reconstruct geometry...\n";

    // 1. Xác định Offset bắt đầu của Partition
    ParEntry &p = mbr.partitions[partitionID];
    uint64_t partStartOffset = (uint64_t)p.lbaFirst * 512ULL;

    // Biến để lưu kết quả tìm kiếm
    uint64_t fat1StartOffset = 0;
    uint64_t fat2StartOffset = 0;
    bool foundFAT1 = false;

    // 2. SCANNING: Quét 2048 sector đầu tiên của partition để tìm chữ ký bảng FAT
    // Signature của FAT32 entry 0 thường là: F8 FF FF 0F (cho Hard Disk)
    uint8_t buffer[512];

    // Giới hạn quét: Thường Reserved sectors khoảng 32-100 sector. Quét 4000 cho chắc.
    int scanLimit = 4000;

    for (int i = 1; i < scanLimit; i++)
    {
        uint64_t currentOffset = partStartOffset + (uint64_t)i * 512ULL;

        if (readBytes(currentOffset, buffer, 512) != 512)
            break;

        // Kiểm tra chữ ký đầu bảng FAT (Cluster 0 entry)
        // 0xF8: Media descriptor for Hard Disk
        // 0xFF 0xFF 0x0F: High bits
        if (buffer[0] == 0xF8 && buffer[1] == 0xFF && buffer[2] == 0xFF && buffer[3] == 0x0F)
        {
            if (!foundFAT1)
            {
                cout << "   -> Found potential FAT #1 at relative sector: " << i << "\n";
                fat1StartOffset = currentOffset;
                foundFAT1 = true;

                // Tạm thời giả định Reserved Sectors
                this->bootSector.reservedSectors = (uint16_t)i;
            }
            else
            {
                // Nếu tìm thấy chữ ký lần nữa, đó có thể là FAT #2
                cout << "   -> Found potential FAT #2 at relative sector: " << i << "\n";
                fat2StartOffset = currentOffset;
                break; // Tìm thấy cả 2 là đủ
            }
        }
    }

    if (fat1StartOffset == 0 || fat2StartOffset == 0)
    {
        cerr << "[FAILED] Could not locate FAT tables signature. Cannot reconstruct.\n";
        return false;
    }

    // 3. TÍNH TOÁN CÁC THÔNG SỐ
    cout << "   -> Reconstructing Boot Sector parameters...\n";

    // A. Bytes Per Sector (Giả định chuẩn)
    this->bootSector.bytesPerSector = 512;

    // B. Sectors Per FAT
    // Khoảng cách giữa 2 bảng FAT chia cho kích thước sector
    uint64_t distanceBytes = fat2StartOffset - fat1StartOffset;
    this->bootSector.sectorsPerFat = (uint32_t)(distanceBytes / 512);

    // C. Number of FATs (Giả định chuẩn)
    this->bootSector.numFATs = 2;

    // D. Hidden Sectors (LBA First của partition)
    this->bootSector.hiddenSectors = p.lbaFirst;

    // E. Total Sectors (Lấy từ MBR)
    this->bootSector.totalSectors32 = p.numSectors;

    // F. Root Cluster (Thường là 2)
    this->bootSector.rootCluster = 2;

    // G. Sectors Per Cluster (SPC) - PHẦN KHÓ NHẤT
    // Ta phải đoán (Brute-force). Các giá trị thường gặp: 1, 2, 4, 8, 16, 32, 64.
    // Cách kiểm tra: Tính toán vùng Data, thử đọc Cluster 2 (Root).
    // Nếu dữ liệu trông giống thư mục (có file hợp lệ), thì SPC đúng.

    int possibleSPCs[] = {8, 16, 32, 64, 1, 2, 4, 128};
    bool spcFound = false;

    for (int spc : possibleSPCs)
    {
        this->bootSector.sectorsPerCluster = (uint8_t)spc;

        // Cập nhật lại các biến offset toàn cục của class dựa trên SPC giả định này
        this->fatBegin = fat1StartOffset;
        uint64_t fatSize = (uint64_t)this->bootSector.sectorsPerFat * 512;
        this->dataBegin = this->fatBegin + ((uint64_t)this->bootSector.numFATs * fatSize);

        // Thử đọc Root Cluster (Cluster 2)
        // Lưu ý: Cluster 2 nằm ngay đầu vùng Data
        uint64_t rootOffset = this->dataBegin;

        uint8_t rootBuf[512];
        readBytes(rootOffset, rootBuf, 512);

        // Kiểm tra xem sector này có phải là Directory không?
        // Directory Entry hợp lệ:
        // - Byte 0: Khác 0 (trừ khi trống hết), khác 0xE5 (nếu đã xóa)
        // - Byte 11 (Attr): 0x10 (Subdir), 0x20 (Archive), 0x0F (LFN), ...
        // - Name: Ký tự in được

        // Kiểm tra entry đầu tiên
        // Root dir thường chứa Volume Label (Attr 0x08) hoặc file/folder hệ thống
        bool looksLikeDir = false;

        // Kiểm tra sơ bộ 1 vài entry
        for (int k = 0; k < 16; k++)
        {
            uint8_t attr = rootBuf[k * 32 + 11];
            uint8_t firstChar = rootBuf[k * 32];

            // Nếu tìm thấy một entry có attribute hợp lệ (Read only, Hidden, System, Vol, Dir, Archive)
            // Và tên file là ký tự đọc được
            if ((attr & 0x3F) != 0 && isalnum(firstChar))
            {
                looksLikeDir = true;
                break;
            }
        }

        if (looksLikeDir)
        {
            cout << "   -> Guessing SectorsPerCluster: " << spc << " [MATCHED Root Dir Content]\n";
            spcFound = true;
            break;
        }
    }

    if (!spcFound)
    {
        cout << "   -> [WARN] Could not determine SectorsPerCluster. Defaulting to 8.\n";
        this->bootSector.sectorsPerCluster = 8;
    }

    // 4. (Tùy chọn) Ghi Boot Sector "giả" này xuống đĩa để các tool khác đọc được
    // Cần phải điền signature 0xAA55
    uint8_t rebuildBuf[512];
    memset(rebuildBuf, 0, 512);
    memcpy(rebuildBuf, &this->bootSector, sizeof(BootSector)); // Copy struct 64 bytes

    // Ghi Signature
    rebuildBuf[510] = 0x55;
    rebuildBuf[511] = 0xAA;

    // Ghi Jump code (JMP SHORT 3C NOP) để Windows nhận diện là bootable (Optional)
    rebuildBuf[0] = 0xEB;
    rebuildBuf[1] = 0x58;
    rebuildBuf[2] = 0x90;

    // Ghi đè vào Sector 0
    cout << "   -> Writing reconstructed Boot Sector to disk...\n";
    vhd.clear();
    vhd.seekp(partStartOffset, std::ios::beg);
    vhd.write((char *)rebuildBuf, 512);
    vhd.flush();

    return true;
}

// ======================================================================
//                       FILE SYSTEM (FAT32)
// ======================================================================
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

    cout << "[INFO] FAT table size: " << fatSizeBytes << " bytes. Reading from offset: 0x"
         << hex << fatBegin << endl;

    // 2. Chuẩn bị buffer và đọc toàn bộ FAT table từ đĩa
    // vector<uint8_t> fatBuffer(fatSizeBytes);

    // ssize_t n = readBytes(fatBegin, fatBuffer.data(), fatSizeBytes);

    // if (n != (ssize_t)fatSizeBytes)
    // {
    //     // Xử lý lỗi đọc
    //     throw runtime_error("Failed to read entire FAT table from disk. Read " +
    //                         to_string(n) + " of " + to_string(fatSizeBytes) + " bytes.");
    // }

    vector<uint8_t> fatBuffer(fatSizeBytes);
    bool isFATValid = false;

    // Thử đọc FAT1
    cout << "[INFO] Reading FAT1...\n";
    if (readBytes(fatBegin, fatBuffer.data(), fatSizeBytes) == (ssize_t)fatSizeBytes)
    {
        uint32_t entry0 = read_u32_le(fatBuffer.data());
        // Entry 0 của FAT32 đĩa cứng thường là 0x0FFFFF8 (Media Type F8)
        if ((entry0 & 0x0FFFFF00) == 0x0FFFFF00)
        {
            isFATValid = true;
        }
    }

    // Nếu FAT1 lỗi, thử đọc FAT2 (Theo kiến trúc thực tế)
    if (!isFATValid && bootSector.numFATs > 1)
    {
        cout << "[WARN] FAT1 corrupted. Attempting to read FAT2 (Redundancy Check)...\n";
        uint64_t fat2Begin = fatBegin + fatSizeBytes; // FAT2 nằm ngay sau FAT1

        // Tái sử dụng buffer để đọc FAT2
        if (readBytes(fat2Begin, fatBuffer.data(), fatSizeBytes) == (ssize_t)fatSizeBytes)
        {
            uint32_t entry0 = read_u32_le(fatBuffer.data());
            if ((entry0 & 0x0FFFFF00) == 0x0FFFFF00)
            {
                cout << "[SUCCESS] FAT2 is valid. Using FAT2 data.\n";
                isFATValid = true;

                // Tự động sửa FAT1 bằng FAT2
                cout << "[FIX] Overwriting corrupted FAT1 with valid FAT2...\n";
                vhd.seekp(fatBegin, ios::beg);
                vhd.write((char *)fatBuffer.data(), fatSizeBytes);
                vhd.flush();
            }
        }
    }

    if (!isFATValid)
    {
        scanAndAutoRepair(bootSector.rootCluster, true);
        throw runtime_error("Critical Error: Both FAT tables are corrupted.");
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

    cout << "[INFO] Loaded FAT table successfully. Total entries (clusters): " << dec << FAT.size() << "\n";
    cout << "       FAT[0] (Media Type): 0x" << hex << FAT[0] << "\n";
    cout << "       FAT[1] (EOC Marker): 0x" << hex << FAT[1] << dec << "\n";

    // Dọn dẹp: Đảm bảo luồng cout không bị ảnh hưởng bởi hex/dec
    cout << dec;
    cout << "[SCAN] Checking directory and FAT structures\n";
    cout << "================================\n";
}

void FAT32Recovery::writeFAT()
{
    // số byte của mỗi bản sao FAT trên đĩa
    const uint64_t bytesPerSector = bootSector.bytesPerSector;
    const uint64_t sectorsPerFAT = bootSector.sectorsPerFat;
    const uint64_t bytesPerFAT = sectorsPerFAT * bytesPerSector;

    // Mỗi mục nhập FAT là 4 byte
    // Chuẩn bị một bộ đệm tạm thời để ghi một bản sao FAT
    vector<uint8_t> buf(bytesPerFAT);
    // Xóa bộ đệm (đặt về 0)
    fill(buf.begin(), buf.end(), 0);

    // Đóng gói vector FAT vào bộ đệm (little-endian 32-bit)
    size_t maxEntries = bytesPerFAT / 4;
    size_t entriesToWrite = min(maxEntries, FAT.size());
    for (size_t i = 0; i < entriesToWrite; ++i)
    {
        uint32_t v = FAT[i] & 0x0FFFFFFF; // 28-bit hợp lệ
        size_t off = i * 4;
        buf[off + 0] = uint8_t(v & 0xFF);
        buf[off + 1] = uint8_t((v >> 8) & 0xFF);
        buf[off + 2] = uint8_t((v >> 16) & 0xFF);
        buf[off + 3] = uint8_t((v >> 24) & 0xFF);
    }

    // Ghi từng bản sao FAT
    for (uint8_t fatIndex = 0; fatIndex < bootSector.numFATs; ++fatIndex)
    {
        uint64_t fatOffset = fatBegin + uint64_t(fatIndex) * bytesPerFAT;
        // di chuyển con trỏ ghi và ghi
        vhd.seekp(fatOffset, ios::beg);
        if (!vhd.good())
        {
            cerr << "[ERROR] seekp failed at offset " << fatOffset << "\n";
            continue;
        }
        vhd.write(reinterpret_cast<const char *>(buf.data()), buf.size());
        if (!vhd.good())
        {
            cerr << "[ERROR] write failed for FAT index " << int(fatIndex) << "\n";
        }
        vhd.flush();
    }
}

void FAT32Recovery::scanAndAutoRepair(uint32_t dirCluster, bool fix)
{
    vector<uint8_t> buf;
    readCluster(dirCluster, buf);

    size_t num = buf.size() / 32;
    bool hasError = false;

    for (size_t i = 0; i < num; i++)
    {
        DirEntry *e = (DirEntry *)(buf.data() + i * 32);

        if (e->isdDir())
        {
            // Nếu là Folder, fileSize luôn = 0 nên ta không thể check theo cách thông thường.
            // Chỉ cần đảm bảo chuỗi FAT không bị đứt (size > 0) là được.
            auto chain = followFAT(e->getStartCluster());
            if (chain.empty() && e->getStartCluster() != 0)
            {
                cout << "[ERROR] Directory " << e->getNameString() << " has empty chain but Valid Start Cluster!\n";
            }
            // Folder hợp lệ thì bỏ qua check size
            continue;
        }

        if (e->name[0] == 0x00 || e->isDeleted() || e->isLFN())
            continue;

        uint32_t start = e->getStartCluster();
        uint32_t need = e->fileSize;

        auto chain = followFAT(start);
        uint32_t bytesPerCluster =
            bootSector.bytesPerSector * bootSector.sectorsPerCluster;

        uint32_t must = (need + bytesPerCluster - 1) / bytesPerCluster;

        if (chain.size() != must)
        {
            hasError = true;

            cout << "[ERROR] Entry " << i
                 << " (" << e->getNameString() << ")"
                 << ": cluster chain size = " << chain.size()
                 << ", expected = " << must << endl;
        }
    }

    if (hasError && fix)
    {
        cout << ">>> Repairing directory and FAT structures..." << endl;
        repairFolderAndClusters(dirCluster); // phase 2
    }
    else if (hasError)
    {
        cout << ">>> Errors detected, but fix = false -> no repair performed." << endl;
    }
    else
    {
        cout << ">>> No inconsistencies found." << endl;
    }
}

// Sửa chữa các mục nhập thư mục (directory entries) và chuỗi FAT (FAT chains) bên dưới một cluster thư mục
// Trả về số lần sửa chữa đã thực hiện
int FAT32Recovery::repairFolderAndClusters(uint32_t dirCluster)
{
    // Tính toán số byte trên mỗi cluster
    const uint32_t bytesPerCluster = uint32_t(bootSector.bytesPerSector) * uint32_t(bootSector.sectorsPerCluster);
    int fixes = 0; // Biến đếm số lần sửa chữa

    // Đọc tất cả các cluster của thư mục vào một bộ đệm duy nhất.
    // Đối với các thư mục trải dài trên nhiều cluster, thao tác này sẽ đọc chúng từng cái một.
    vector<uint8_t> clusterBuf;
    readCluster(dirCluster, clusterBuf); // đọc cluster đầu tiên
    // Nếu thư mục dài, hàm gọi (caller) có thể gọi hàm này cho mỗi chuỗi thư mục;
    // để đơn giản, chúng ta sẽ giả định một thư mục cluster đơn hoặc rằng scanDirectory xử lý nhiều cluster.

    // lặp qua các mục nhập (mỗi mục 32 byte)
    size_t entries = clusterBuf.size() / 32;
    for (size_t ei = 0; ei < entries; ++ei)
    {
        DirEntry *de = reinterpret_cast<DirEntry *>(clusterBuf.data() + ei * 32);

        // bỏ qua các mục nhập trống/đã xóa và LFN (Tên dài)
        if (de->name[0] == 0x00)
            continue; // trống / kết thúc thư mục
        if (de->isDeleted())
            continue;
        if (de->isLFN())
            continue;

        // tính toán cluster bắt đầu
        uint32_t startCluster = ((uint32_t)de->firstClusterHigh << 16) | de->firstClusterLow;
        uint32_t fileSize = de->fileSize;

        if (startCluster == 0)
        {
            // tập tin không có cluster bắt đầu — cố gắng tìm một vùng liên tục
            auto candidate = contiguousGuess(2 /*gợi ý bắt đầu: cluster 2*/, fileSize);
            if (!candidate.empty())
            {
                // Đánh dấu (Claim) các cluster ứng cử viên
                for (size_t k = 0; k < candidate.size(); ++k)
                {
                    uint32_t c = candidate[k];
                    uint32_t next = (k + 1 < candidate.size()) ? candidate[k + 1] : 0x0FFFFFFF;
                    FAT[c] = next & 0x0FFFFFFF;
                }
                // cập nhật các trường cluster bắt đầu của mục nhập thư mục
                uint32_t newStart = candidate.front();
                de->firstClusterHigh = uint16_t((newStart >> 16) & 0xFFFF);
                de->firstClusterLow = uint16_t(newStart & 0xFFFF);
                ++fixes;
            }
            continue;
        }

        // theo dõi chuỗi FAT hiện tại
        vector<uint32_t> chain = followFAT(startCluster);

        // số lượng cluster cần thiết cho kích thước tập tin
        uint32_t needClusters = (fileSize + bytesPerCluster - 1) / bytesPerCluster;

        // Nếu chuỗi trống, quá ngắn hoặc có đánh dấu không hợp lệ, cố gắng sửa
        bool badChain = false;
        if (chain.empty())
            badChain = true;
        else if (chain.size() < needClusters)
            badChain = true;
        else
        {
            // kiểm tra bất kỳ cluster nào được đánh dấu là xấu/không hợp lệ trong chuỗi
            for (auto c : chain)
            {
                if (c < 2 || c >= totalClusters + 2)
                {
                    badChain = true;
                    break;
                }
                uint32_t entry = FAT[c] & 0x0FFFFFFF;
                // xem xét cluster trống (0) hoặc reserved (0x00000000) là xấu
                if (entry == 0)
                {
                    badChain = true;
                    break;
                }
            }
        }

        if (!badChain)
            continue; // chuỗi có vẻ OK

        // Thử đoán một chuỗi liên tục bắt đầu từ startCluster (hoặc gần đó)
        auto candidate = contiguousGuess(startCluster, fileSize);
        if (candidate.empty())
        {
            // dự phòng: thử đoán toàn cục bắt đầu từ cluster 2
            candidate = contiguousGuess(2, fileSize);
        }

        if (!candidate.empty())
        {
            // Đánh dấu các cluster của chuỗi cũ là trống (nếu nằm trong phạm vi hợp lệ)
            for (auto c : chain)
            {
                if (c >= 2 && c < FAT.size())
                {
                    FAT[c] = 0; // trống
                }
            }
            // Ghi chuỗi ứng cử viên vào FAT
            for (size_t k = 0; k < candidate.size(); ++k)
            {
                uint32_t c = candidate[k];
                uint32_t next = (k + 1 < candidate.size()) ? candidate[k + 1] : 0x0FFFFFFF;
                FAT[c] = next & 0x0FFFFFFF;
            }
            // Cập nhật các trường cluster bắt đầu của mục nhập thư mục nếu thay đổi
            uint32_t newStart = candidate.front();
            if (newStart != startCluster)
            {
                de->firstClusterHigh = uint16_t((newStart >> 16) & 0xFFFF);
                de->firstClusterLow = uint16_t(newStart & 0xFFFF);
            }
            ++fixes;
        }
        else
        {
            // không thể tìm thấy ứng cử viên liên tục; giữ nguyên nhưng cảnh báo (tùy chọn)
            cerr << "[ERROR] unable to repair entry at dir cluster " << dirCluster
                 << " entry index " << ei << " startCluster=" << startCluster << " size=" << fileSize << "\n";
        }
    } // for each dir entry

    if (fixes > 0)
    {
        // ghi lại cluster thư mục đã sửa đổi (cập nhật nội dung thư mục trên đĩa)
        uint64_t dirOffset = cluster2Offset(dirCluster);
        vhd.seekp(dirOffset, ios::beg);
        vhd.write(reinterpret_cast<const char *>(clusterBuf.data()), clusterBuf.size());
        vhd.flush();

        // ghi lại các FAT đã sửa đổi vào đĩa
        writeFAT();
    }

    return fixes;
}

// Hàm đoán chuỗi cluster liên tục cho file dựa trên fileSize
vector<uint32_t> FAT32Recovery::contiguousGuess(uint32_t startHint, uint32_t fileSize) const
{
    vector<uint32_t> result;

    const uint32_t bytesPerCluster =
        bootSector.bytesPerSector * bootSector.sectorsPerCluster;

    if (fileSize == 0)
        return result;

    uint32_t need = (fileSize + bytesPerCluster - 1) / bytesPerCluster;
    uint32_t total = totalClusters; // số cluster hữu dụng

    // Helper: kiểm tra đoạn free
    auto isRangeFree = [&](uint32_t start, uint32_t len) -> bool
    {
        for (uint32_t i = 0; i < len; i++)
        {
            uint32_t c = start + i;
            if (c >= FAT.size())
                return false;
            if ((FAT[c] & 0x0FFFFFFF) != 0)
                return false; // không free
        }
        return true;
    };

    // ----------------------------------------------------
    // 1. Thử đoán bắt đầu từ startHint
    // ----------------------------------------------------
    if (startHint >= 2 && startHint + need < FAT.size())
    {
        if (isRangeFree(startHint, need))
        {
            result.reserve(need);
            for (uint32_t i = 0; i < need; i++)
                result.push_back(startHint + i);
            return result;
        }
    }

    // ----------------------------------------------------
    // 2. Dò toàn FAT để tìm 1 đoạn free đủ dài
    // ----------------------------------------------------
    for (uint32_t c = 2; c < FAT.size() - need; c++)
    {
        if (isRangeFree(c, need))
        {
            result.reserve(need);
            for (uint32_t i = 0; i < need; i++)
                result.push_back(c + i);
            return result;
        }
    }

    // ----------------------------------------------------
    // 3. Không đoán được
    // ----------------------------------------------------
    return result;
}

// ======================================================================
//                       DELETED FILE RECOVERY
// ======================================================================
// 1. PHÂN TÍCH XUNG ĐỘT (Collision Detection Strategy)
vector<DeletedFileInfo> FAT32Recovery::analyzeRecoveryCandidates(uint32_t dirCluster)
{
    vector<DeletedFileInfo> candidates;
    vector<uint8_t> buf;
    try
    {
        readCluster(dirCluster, buf);
    }
    catch (...)
    {
        return candidates;
    }

    size_t numEntries = buf.size() / 32;
    uint32_t bytesPerCluster = bootSector.bytesPerSector * bootSector.sectorsPerCluster;

    // --- BƯỚC 1: Thu thập (Census) ---
    for (size_t i = 0; i < numEntries; ++i)
    {
        const DirEntry *entry = reinterpret_cast<const DirEntry *>(buf.data() + (i * 32));

        // Chỉ lấy các entry đánh dấu xóa (0xE5) và không phải tên dài (LFN)
        if (entry->name[0] == 0xE5 && !entry->isLFN())
        {
            DeletedFileInfo info;
            info.entryIndex = (int)i;
            info.name = entry->getNameString();
            info.size = entry->fileSize;
            info.startCluster = entry->getStartCluster();
            info.isDir = entry->isdDir(); // Lấy cờ folder

            // Lấy timestamps
            info.lastWriteTime = entry->getWriteTimestamp();
            info.creationTime = entry->getCreationTimestamp();

            info.isRecoverable = true;
            info.statusReason = "Good";

            candidates.push_back(info);
        }
    }

    // --- BƯỚC 2: Map Cluster Claims ---
    // Key: Cluster ID, Value: List of file indices wanting this cluster
    map<uint32_t, vector<int>> clusterClaims;

    for (int fileIdx = 0; fileIdx < (int)candidates.size(); ++fileIdx)
    {
        auto &file = candidates[fileIdx];
        if (file.size == 0)
            continue; // File rỗng không chiếm cluster

        uint32_t needed = (file.size + bytesPerCluster - 1) / bytesPerCluster;

        // Giả định file liên tục (Contiguous Assumption)
        for (uint32_t c = 0; c < needed; ++c)
        {
            uint32_t currentClus = file.startCluster + c;

            // Nếu cluster vượt quá giới hạn đĩa
            if (currentClus >= totalClusters + 2)
            {
                file.isRecoverable = false;
                file.statusReason = "Invalid Range";
                break;
            }
            clusterClaims[currentClus].push_back(fileIdx);
        }
    }

    // --- BƯỚC 3: Xử lý xung đột (Arbitration) ---
    for (auto const &[clusterID, claimants] : clusterClaims)
    {
        // A. Kiểm tra với bảng FAT thực tế (File đang sống)
        if ((FAT[clusterID] & 0x0FFFFFFF) != 0)
        {
            for (int idx : claimants)
            {
                candidates[idx].isRecoverable = false;
                candidates[idx].statusReason = "Overwritten by Active File";
            }
            continue;
        }

        // B. Kiểm tra xung đột giữa các file đã xóa (Deleted vs Deleted)
        if (claimants.size() > 1)
        {
            int winnerIdx = claimants[0];

            // So sánh từng cặp để tìm người chiến thắng
            for (size_t i = 1; i < claimants.size(); ++i)
            {
                int challengerIdx = claimants[i];
                auto &winner = candidates[winnerIdx];
                auto &challenger = candidates[challengerIdx];

                // === LOGIC: Creation vs Last Write ===
                // Nếu B được TẠO RA (Created) sau khi A đã GHI XONG (LastWrite)
                // => B là kẻ đến sau đè lên A.
                if (challenger.creationTime > winner.lastWriteTime)
                {
                    winnerIdx = challengerIdx;
                }
                else if (winner.creationTime > challenger.lastWriteTime)
                {
                    // Winner vẫn thắng, không đổi
                }
                else
                {
                    // Fallback: Ai có Last Write mới hơn thì thắng
                    if (challenger.lastWriteTime > winner.lastWriteTime)
                    {
                        winnerIdx = challengerIdx;
                    }
                }
            }

            // Loại bỏ những kẻ thua cuộc
            for (int idx : claimants)
            {
                if (idx != winnerIdx)
                {
                    candidates[idx].isRecoverable = false;
                    candidates[idx].statusReason = "Collision (Lost Time Check)";
                }
            }
        }
    }
    return candidates;
}

// 2. KHÔI PHỤC TẠI CHỖ (In-Place Restore)
bool FAT32Recovery::restoreDeletedFile(uint32_t dirCluster, int entryIndex, char newChar)
{
    cout << "[RESTORE] Processing entry " << entryIndex << " in dir " << dirCluster << "...\n";

    // A. Đọc Directory Cluster
    vector<uint8_t> dirBuf;
    try
    {
        readCluster(dirCluster, dirBuf);
    }
    catch (...)
    {
        return false;
    }

    DirEntry *de = reinterpret_cast<DirEntry *>(dirBuf.data() + (entryIndex * 32));
    if (de->name[0] != 0xE5)
        return false;

    uint32_t start = de->getStartCluster();
    uint32_t size = de->fileSize;
    uint32_t bytesPerClus = bootSector.bytesPerSector * bootSector.sectorsPerCluster;
    uint32_t needed = (size + bytesPerClus - 1) / bytesPerClus;
    if (size == 0)
        needed = 0;

    // B. Chuẩn bị danh sách cluster cần chiếm (Claim List)
    vector<uint32_t> chainToClaim;
    if (needed > 0)
    {
        for (uint32_t i = 0; i < needed; i++)
        {
            uint32_t c = start + i;
            // Check an toàn lần cuối
            if (c >= FAT.size() || (FAT[c] & 0x0FFFFFFF) != 0)
            {
                cerr << "[ERR] Collision detected at " << c << " during write phase. Aborting.\n";
                return false;
            }
            chainToClaim.push_back(c);
        }
    }

    // C. Verify (Optional): Đọc thử cluster đầu tiên kiểm tra Signature
    if (!chainToClaim.empty() && !de->isdDir())
    {
        if (!verifyFileSignature(chainToClaim[0], de->getNameString()))
        {
            cout << "[WARN] Signature mismatch. Restoring anyway but file might be junk.\n";
        }
    }

    // D. THỰC HIỆN GHI (Write Phase)

    // 1. Sửa Dir Entry
    de->name[0] = (uint8_t)newChar;

    // 2. Cập nhật FAT Chain
    if (!chainToClaim.empty())
    {
        for (size_t i = 0; i < chainToClaim.size(); i++)
        {
            uint32_t cur = chainToClaim[i];
            uint32_t next = (i == chainToClaim.size() - 1) ? 0x0FFFFFFF : chainToClaim[i + 1];
            FAT[cur] = next;
        }
        writeFAT(); // Ghi 2 bảng FAT xuống đĩa
    }

    // 3. Ghi lại Directory Cluster
    uint64_t dirOffset = cluster2Offset(dirCluster);
    vhd.clear();
    vhd.seekp(dirOffset, ios::beg);
    vhd.write(reinterpret_cast<const char *>(dirBuf.data()), dirBuf.size());
    vhd.flush();

    return true;
}

// 3. KHÔI PHỤC ĐỆ QUY (Recursive Tree)
void FAT32Recovery::restoreTree(uint32_t dirClusterOfParent, int entryIndex)
{
    cout << "\n[TREE] Starting recursive restore...\n";

    // Bước 1: Cứu cha trước
    if (!restoreDeletedFile(dirClusterOfParent, entryIndex, '_'))
    {
        cout << "[TREE] Parent restore failed.\n";
        return;
    }

    // Đọc lại để lấy start cluster chính xác (sau khi restore)
    vector<uint8_t> buf;
    readCluster(dirClusterOfParent, buf);
    const DirEntry *de = reinterpret_cast<const DirEntry *>(buf.data() + (entryIndex * 32));

    if (de->isdDir())
    {
        recursiveRestoreLoop(de->getStartCluster());
    }
}

void FAT32Recovery::recursiveRestoreLoop(uint32_t currentDirCluster)
{
    cout << "   >>> Diving into cluster " << currentDirCluster << "...\n";

    // Bước 2: Quét tìm con bằng thuật toán Collision Check
    vector<DeletedFileInfo> children = analyzeRecoveryCandidates(currentDirCluster);

    for (const auto &child : children)
    {
        if (child.isRecoverable && child.name != "." && child.name != "..")
        {
            // Bước 3: Cứu con (In-place)
            bool ok = restoreDeletedFile(currentDirCluster, child.entryIndex, '_');

            // Bước 4: Đệ quy nếu con là Folder
            if (ok && child.isDir)
            {
                // Tránh loop vô tận
                if (child.startCluster != currentDirCluster && child.startCluster != 0)
                    recursiveRestoreLoop(child.startCluster);
            }
        }
    }
}

// Helper: Verify Signature đơn giản
bool FAT32Recovery::verifyFileSignature(uint32_t startCluster, string filename)
{
    // Lấy extension
    size_t dotPos = filename.find_last_of(".");
    if (dotPos == string::npos)
        return true;                          // Không có đuôi -> bỏ qua check
    string ext = filename.substr(dotPos + 1); // Cần toUpper nếu muốn chắc chắn

    vector<uint8_t> buf;
    try
    {
        readCluster(startCluster, buf);
    }
    catch (...)
    {
        return false;
    }
    if (buf.size() < 4)
        return false;

    // Check mẫu vài loại phổ biến
    if (ext == "JPG" || ext == "JPEG")
        return buf[0] == 0xFF && buf[1] == 0xD8;
    if (ext == "PNG")
        return buf[0] == 0x89 && buf[1] == 'P' && buf[2] == 'N' && buf[3] == 'G';

    return true;
}
// ======================================================================
//                       Scanning & recovery routines
// ======================================================================
vector<uint32_t> FAT32Recovery::followFAT(uint32_t startCluster) const
{
    vector<uint32_t> chain;

    // 0. Kiểm tra điều kiện tiên quyết
    // Nếu bảng FAT chưa load hoặc startCluster là 0 (file rỗng), trả về rỗng ngay.
    if (FAT.empty())
    {
        cerr << "[ERR] FAT table is not loaded yet.\n";
        return chain;
    }
    if (startCluster == 0)
    {
        return chain; // File rỗng, không có lỗi
    }

    // Dự đoán kích thước vector để giảm chi phí cấp phát bộ nhớ liên tục
    // (Optional: Giả sử file trung bình có vài cluster)
    chain.reserve(32);

    // Sử dụng Set để phát hiện vòng lặp (Safety mechanism)
    set<uint32_t> visited;

    uint32_t current = startCluster;
    const uint32_t FAT32_MASK = 0x0FFFFFFF;
    const uint32_t EOC_MARK = 0x0FFFFFF8;
    const uint32_t BAD_CLUS = 0x0FFFFFF7;

    while (true)
    {
        // 1. Kiểm tra biên (Boundary Check)
        // Cluster < 2 là reserved (trừ khi tính toán sai), >= size là lỗi
        if (current < 2 || current >= FAT.size())
        {
            cerr << "[WARN] Chain points to invalid cluster index: " << current << " (Out of FAT bounds)\n";
            break;
        }

        // 2. Kiểm tra vòng lặp (Loop Detection)
        // Nếu cluster đã tồn tại trong set -> Có vòng lặp
        if (visited.find(current) != visited.end())
        {
            cerr << "[WARN] FAT Cycle detected at cluster " << current << ". Cutting chain here.\n";
            break;
        }

        // Ghi nhận cluster
        visited.insert(current);
        chain.push_back(current);

        // 3. Đọc giá trị tiếp theo
        uint32_t next = FAT[current] & FAT32_MASK;

        // 4. Các điều kiện dừng

        // A. End of Chain (EOC)
        if (next >= EOC_MARK)
        {
            // Đây là kết thúc bình thường, không cần log lỗi
            break;
        }

        // B. Bad Cluster
        if (next == BAD_CLUS)
        {
            cerr << "[WARN] Chain hit BAD CLUSTER at index " << current << "\n";
            break;
        }

        // C. Free Cluster (0) - Broken Chain
        if (next == 0)
        {
            // Trong recovery, file đang có dữ liệu mà trỏ về 0 nghĩa là mất đoạn sau.
            cerr << "[WARN] Chain broken (points to FREE/0) at cluster " << current << "\n";
            break;
        }

        // 5. Di chuyển tiếp
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

uint64_t FAT32Recovery::cluster2Offset(uint32_t cluster) const
{
    if (cluster < 2)
        throw runtime_error("Invalid cluster number");

    return dataBegin + uint64_t(cluster - 2) * bootSector.sectorsPerCluster * bootSector.bytesPerSector;
}