#ifndef __FAT32__
#define __FAT32__

#pragma once
#include <iostream>
#include <cstdint>
#include <string>
#include <vector>

using namespace std;

// Ultils
static inline uint16_t read_u16_le(const uint8_t *p) { return uint16_t(p[0]) | (uint16_t(p[1]) << 8); }
static inline uint16_t read_u32_le(const uint8_t *p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }

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
    int fd;
    string imagePath;

    // Boot Sector
    uint16_t bytesPerSecor;
    uint16_t sectorPerCluster;
    uint16_t reservedSectors;
    uint8_t numFATs;
    uint32_t sectorPerFat;
    uint32_t rootCluster;

    // Computed offsets
    uint32_t fatBegin;
    uint32_t dataBegin;
    uint32_t totalClusters;

    // FAT
    vector<uint32_t> FAT;

    // Low level read
    ssize_t readBytes(uint64_t offset, void *buf, size_t size) const;
    ssize_t writeAll(int fd_out, const void *buf, size_t size) const;

    // format short 8.3 name
    static string formatShortName(const uint8_t name[11]);

    // Boot sector parser and validator
    bool parseAndValidateBootSector(const uint8_t *buffer);


public:
    FAT32Recovery(const string &path); // Construct
    ~FAT32Recovery();                  // Deconstruct

    // Load fields
    void readBootSector(); // Boot sector paeser
    void loadFAT();        // Load FAT table

    // Scanning & recovery routines
    void scanRoot();
    void scanDirectory(uint32_t startCluster);
    vector<uint32_t> followFAT(uint32_t startCluster) const;
    vector<uint32_t> contiguousGuess(uint32_t startCluster, uint32_t fileSize) const;

    // Recover file with given start cluster and file size (output -> outPath)
    // Will write exactly fileSize bytes (so it truncates last cluster properly)
    void recoverFile(uint32_t startCluster, uint32_t fileSize, const string &outPath);

    // Utils
    uint64_t cluster2Offset(uint32_t cluster) const;
    void readCluster(uint32_t cluster, vector<uint8_t> &buffer) const;

    // Boot sector backup fixer
    bool fixBootSectorBackup();s
};

#endif //__FAT32__