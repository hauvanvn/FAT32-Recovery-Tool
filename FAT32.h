#ifndef __FAT32__
#define __FAT32__

#pragma once
#include <iostream>
#include <fstream>
#include <cstdint>
#include <string>
#include <vector>
#include <set>

using namespace std;

// Ultils
static inline uint16_t read_u16_le(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static inline uint16_t read_u32_le(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }
// typedef signed long long ssize_t;

#pragma pack(push, 1)
// Partition struct
struct ParEntry
{
    uint8_t status;        // 0x80 = active
    uint8_t chsFirst[3];   // CHS of first sector
    uint8_t partitionType; // Partition type
    uint8_t chsLast[3];    // CHS of last sector
    uint32_t lbaFirst;     // LBA of first sector
    uint32_t numSectors;   // Number of sectors
};

struct MBR
{
    uint8_t bootloader[446];
    ParEntry partitions[4];
    uint16_t signature; // 0xAA55
};

// Boot Sector
struct BootSector
{
    uint8_t jumpBoot[3]; // offset 0x00
    uint8_t oemName[8];  // offset 0x03

    uint16_t bytesPerSector;   // offset 0x0B
    uint8_t sectorsPerCluster; // offset 0x0D
    uint16_t reservedSectors;  // offset 0x0E
    uint8_t numFATs;           // offset 0x10
    uint16_t rootEntryCount;   // offset 0x11 (always 0 in FAT32)
    uint16_t totalSectors16;   // offset 0x13
    uint8_t media;             // offset 0x15
    uint16_t fatSize16;        // offset 0x16
    uint16_t sectorsPerTrack;  // offset 0x18
    uint16_t numHeads;         // offset 0x1A
    uint32_t hiddenSectors;    // offset 0x1C   (important!)
    uint32_t totalSectors32;   // offset 0x20   (important!)

    // FAT32 Extended
    uint32_t sectorsPerFat; // offset 0x24   (FAT size)
    uint16_t extFlags;      // offset 0x28
    uint16_t fsVersion;     // offset 0x2A
    uint32_t rootCluster;   // offset 0x2C   (root dir)
    uint16_t fsInfo;        // offset 0x30
    uint16_t bkBootSector;  // offset 0x32
    uint8_t reserved[12];   // offset 0x34
};
#pragma pack(pop)

// Directory struct
struct DirEntry
{
    uint8_t name[11];
    uint8_t attr;
    uint8_t reserved[10];
    uint16_t time;
    uint16_t date;
    uint16_t firstClusterHigh;
    uint16_t firstClusterLow;
    uint32_t fileSize;

    bool isDeleted() const;
    bool isLFN() const;
    bool isdDir() const;
    uint32_t getStartCluster() const;
};

class FAT32Recovery
{
private:
    // Disk
    fstream vhd;
    string imagePath;

    // MBR
    MBR mbr;

    // Boot Sector
    BootSector bootSector;

    // Computed offsets
    uint32_t fatBegin;
    uint32_t dataBegin;
    uint32_t totalClusters;

    // FAT
    vector<uint32_t> FAT;

    // Low level read
    ssize_t readBytes(uint64_t offset, void *buf, size_t size) const;
    void writeAll(std::ostream &out, const void *buf, size_t size) const;

    // format short 8.3 name
    static string formatShortName(const uint8_t name[11]);

    // Boot sector parser and validator
    bool parseAndValidateBootSector(const uint8_t *buffer);

    // I testing code here
    void rawRecoverFile(uint32_t startCluster, uint32_t fileSize, const string &destPath);
    string restoreDeletedName(const uint8_t name[11]);

public:
    FAT32Recovery(const string &path); // Construct
    ~FAT32Recovery();                  // Deconstruct

    // MBR fields
    void readMBR();
    bool validateAndFixPartition(int index);

    // Boot Sector fields
    void listPartition();
    void readBootSector(int partitionID);                    // Boot sector paeser
    bool fixBootSectorBackup(uint64_t partitionStartOffset); // Boot sector backup fixer

    // FAT fields
    void loadFAT(); // Load FAT table
    void writeFAT();

    // Scanning & recovery routines
    void scanRoot();
    void scanDirectory(uint32_t startCluster);
    vector<uint32_t> followFAT(uint32_t startCluster) const;
    vector<uint32_t> contiguousGuess(uint32_t startCluster, uint32_t fileSize) const;

    // Recover file with given start cluster and file size (output -> outPath)
    // Will write exactly fileSize bytes (so it truncates last cluster properly)
    void recoverFile(uint32_t startCluster, uint32_t fileSize, const string &outPath);
    void recoverDeletedFilesInDir(uint32_t dirCluster, const string &outputFolder);
    void recoverAllRecursively(uint32_t cluster, const string &hostPath);

    // Utils
    uint64_t cluster2Offset(uint32_t cluster) const;
    void readCluster(uint32_t cluster, vector<uint8_t> &buffer) const;
};

#endif //__FAT32__