#ifndef __FAT32__
#define __FAT32__

#pragma once
#include <iostream>
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <map> // Thêm map cho xử lý xung đột

using namespace std;

// Utils
static inline uint16_t read_u16_le(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static inline uint32_t read_u32_le(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
typedef signed long long ssize_t;

// Struct lưu thông tin file bị xóa (Dùng cho phân tích)
struct DeletedFileInfo
{
    int entryIndex; // Index trong Directory Cluster
    string name;
    uint32_t size;
    uint32_t startCluster;

    // Timestamps để so sánh xung đột
    uint32_t lastWriteTime;
    uint32_t creationTime;

    bool isRecoverable;
    string statusReason; // Lý do (Good, Collision, Overwritten...)
    bool isDir;          // Cờ đánh dấu là Folder
};

#pragma pack(push, 1)
struct ParEntry
{
    uint8_t status;
    uint8_t chsFirst[3];
    uint8_t partitionType;
    uint8_t chsLast[3];
    uint32_t lbaFirst;
    uint32_t numSectors;
};

struct MBR
{
    uint8_t bootloader[446];
    ParEntry partitions[4];
    uint16_t signature;
};

struct BootSector
{
    uint8_t jumpBoot[3];
    uint8_t oemName[8];
    uint16_t bytesPerSector;
    uint8_t sectorsPerCluster;
    uint16_t reservedSectors;
    uint8_t numFATs;
    uint16_t rootEntryCount;
    uint16_t totalSectors16;
    uint8_t media;
    uint16_t fatSize16;
    uint16_t sectorsPerTrack;
    uint16_t numHeads;
    uint32_t hiddenSectors;
    uint32_t totalSectors32;
    uint32_t sectorsPerFat;
    uint16_t extFlags;
    uint16_t fsVersion;
    uint32_t rootCluster;
    uint16_t fsInfo;
    uint16_t bkBootSector;
    uint8_t reserved[12];
};

// CẬP NHẬT STRUCT QUAN TRỌNG
struct DirEntry
{
    uint8_t name[11]; // 0x00
    uint8_t attr;     // 0x0B

    // --- KHUI RESERVED RA ĐỂ LẤY CREATION TIME ---
    uint8_t ntRes;        // 0x0C
    uint8_t crtTimeTenth; // 0x0D
    uint16_t crtTime;     // 0x0E (Creation Time)
    uint16_t crtDate;     // 0x10 (Creation Date)
    uint16_t lastAccDate; // 0x12
    // ---------------------------------------------

    uint16_t firstClusterHigh; // 0x14
    uint16_t time;             // 0x16 (Last Write Time)
    uint16_t date;             // 0x18 (Last Write Date)
    uint16_t firstClusterLow;  // 0x1A
    uint32_t fileSize;         // 0x1C

    bool isDeleted() const;
    bool isLFN() const;
    bool isdDir() const;
    uint32_t getStartCluster() const;
    string getNameString() const;

    // Helper lấy timestamp dạng số nguyên (Date << 16 | Time)
    uint32_t getWriteTimestamp() const;
    uint32_t getCreationTimestamp() const;
};
#pragma pack(pop)

class FAT32Recovery
{
private:
    fstream vhd;
    string imagePath;
    MBR mbr;
    BootSector bootSector;

    uint32_t fatBegin;
    uint32_t dataBegin;
    uint32_t totalClusters;
    vector<uint32_t> FAT;

    ssize_t readBytes(uint64_t offset, void *buf, size_t size) const;
    void writeAll(std::ostream &out, const void *buf, size_t size) const;
    static string formatShortName(const uint8_t name[11]);
    bool parseAndValidateBootSector(const uint8_t *buffer);

    // Helper cho đệ quy
    void recursiveRestoreLoop(uint32_t currentDirCluster);
    // Helper kiểm tra chữ ký file (Optional safety check)
    bool verifyFileSignature(uint32_t startCluster, string filename);

public:
    FAT32Recovery(const string &path);
    ~FAT32Recovery();

    // Init logic
    void readMBR();
    bool validateAndFixPartition(int index);
    void listPartition();
    void readBootSector(int partitionID);
    bool fixBootSectorBackup(uint64_t partitionStartOffset);
    bool reconstructBootSector(int partitionID);
    void loadFAT(bool autoRepair);

    // Core FAT operations
    void writeFAT();
    void scanAndAutoRepair(uint32_t dirCluster, bool fix);
    int repairFolderAndClusters(uint32_t dirCluster);
    vector<uint32_t> contiguousGuess(uint32_t startCluster, uint32_t fileSize) const;
    vector<uint32_t> followFAT(uint32_t startCluster) const;

    // Utils
    uint64_t cluster2Offset(uint32_t cluster) const;
    void readCluster(uint32_t cluster, vector<uint8_t> &buffer) const;

    // --- RECOVERY FUNCTIONS (NEW) ---

    // 1. Phân tích xung đột & tìm ứng viên (Collision Detection)
    vector<DeletedFileInfo> analyzeRecoveryCandidates(uint32_t dirCluster);

    // 2. Khôi phục 1 file/folder tại chỗ (In-Place)
    bool restoreDeletedFile(uint32_t dirCluster, int entryIndex, char newChar);

    // 3. Khôi phục đệ quy cả cây thư mục (Recursive Tree)
    void restoreTree(uint32_t dirClusterOfParent, int entryIndex);

    // 4. Xuất file ra ngoài (Export)
    void recoverFile(uint32_t startCluster, uint32_t fileSize, const string &outPath);
};

#endif //__FAT32__