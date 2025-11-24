#include "FAT32.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdexcept>
#include <cstring>
#include <cerrno>

// ================================ DIRENTRY METHODS ====================================
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

// ================================ CONSTRUCT/DECONTRUCT ================================
FAT32Recovery::FAT32Recovery(const string &path) : imagePath(path)
{
    fd = -1;
    bytesPerSecor = 0;
    sectorPerCluster = 0;
    reservedSectors = 0;
    numFATs = 0;
    sectorPerFat = 0;
    rootCluster = 0;
    fatBegin = 0;
    dataBegin = 0;
    totalClusters = 0;

    //fd = open(imagePath.c_str(), O_RDONLY);
    fd = open(imagePath.c_str(), O_RDWR);
    if (fd < 0)
    {
        throw runtime_error(string("Open failed:") + strerror(errno));
    }

    readBootSector();
    loadFAT();
}

FAT32Recovery::~FAT32Recovery()
{
    if (fd >= 0)
        close(fd);
}

// ================================ LOW LEVEL READ ======================================
string FAT32Recovery::formatShortName(const uint8_t name[11])
{
    string res;
    for (int i = 0; i < 8; ++i)
    {
        if (name[i] == ' ')
            break;
        res.push_back(char(name[i]));
    }

    string ext;
    for (int i = 8; i < 11; ++i)
    {
        if (name[i] == ' ')
            break;
        ;
        ext.push_back(name[i]);
    }

    if (!ext.empty())
        res += "." + res;
    return res;
}

ssize_t FAT32Recovery::readBytes(uint64_t offset, void *buf, size_t size) const
{
    ssize_t r = pread(fd, buf, size, offset);
    if (r < 0)
    {
        return -1;
    }

    return r;
}

ssize_t FAT32Recovery::writeAll(int fd_out, const void *buf, size_t size) const
{
    size_t written = 0;
    const uint8_t *p = (const uint8_t *)buf;
    while (written < size)
    {
        ssize_t w = write(fd_out, p + written, size - written);
        if (w <= 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }

        written += w;
    }

    return written;
}

// ================================ BOOT SECTOR PARSER ==================================
bool FAT32Recovery::parseAndValidateBootSector(const uint8_t *bs)
{
    // Check signature
    uint16_t signature = read_u16_le(bs + 510);
    if (signature != 0xAA55)
        return false;

    // Read fields
    uint16_t temp_bytesPerSector = read_u16_le(bs + 11);
    uint8_t temp_sectorPerCluster = bs[13];
    uint16_t temp_reservedSectors = read_u16_le(bs + 14);
    uint8_t temp_numFATs = bs[16];
    uint32_t temp_sectorPerFat = read_u32_le(bs + 36);
    uint32_t temp_rootCluster = read_u32_le(bs + 44);

    // Basic validation
    // Bytes per sector should be 512, 1024, 2048, or 4096, ...
    if (temp_bytesPerSector == 0 || (temp_bytesPerSector % 512) != 0) return false;
    // Sector per cluster should be power of 2 and <= 128
    if (temp_sectorPerCluster == 0 || temp_sectorPerCluster > 128 || (temp_sectorPerCluster & (temp_sectorPerCluster - 1)) != 0) return false;
    // Reserved sectors should be at least 1
    if (temp_reservedSectors < 1) return false;
    // Number of FATs should be 1 or 2
    if (temp_numFATs < 1 || temp_numFATs > 2) return false;
    // Sector per FAT should be non-zero
    if (temp_sectorPerFat == 0) return false;
    // Root cluster should be at least 2
    if (temp_rootCluster < 2) return false;

    // If all validations pass, assign to member variables
    bytesPerSecor = temp_bytesPerSector;
    sectorPerCluster = temp_sectorPerCluster;
    reservedSectors = temp_reservedSectors;
    numFATs = temp_numFATs;
    sectorPerFat = temp_sectorPerFat;
    rootCluster = temp_rootCluster;

    return true;
}

void FAT32Recovery::readBootSector()
{
    uint8_t bs[512];
    bool valid = false;

    // Try reading Sector 0 (Primary Boot Sector)===
    cout << "[INFO] Checking Main Boot Sector (Sector 0)..." << endl;
    if (readBytes(0, bs, sizeof(bs)) == (ssize_t)sizeof(bs))
    {
        if (parseAndValidateBootSector(bs))
        {
            cout << "OK :)" << endl;
            valid = true;
        }
        else
        {
            cout << "Invalid :(" << endl;
        }
    }
    
    // If Primary Boot Sector is invalid, try reading Sector 6 (Backup Boot Sector)===
    if (!valid)
    {
        cout << "[WARNING] Main Boot Sector corrupted. Attempting Backup Boot Sector (Sector 6)..." << endl;
        // Sector 6 offset = 6 * 512 (assuming 512 bytes per sector, or read from existing bytesPerSector if available)
        if (readBytes(6 * 512, bs, sizeof(bs)) == (ssize_t)sizeof(bs))
        {
            if (parseAndValidateBootSector(bs))
            {
                cout << "OK :). Recovered parameters from Backup." << endl;
                valid = true;
                // fixBootSectorBackup(); // Optionally fix the primary boot sector later
            }
            else
            {
                cout << "Invalid :(" << endl;
            }
        }
    }

    if (!valid)
    {
        throw runtime_error("CRITICAL: Both Main and Backup Boot Sectors are corrupted. Cannot mount volume.");
    }

    // Compute offsets
    fatBegin = uint32_t(uint64_t(reservedSectors) * bytesPerSecor);
    dataBegin = fatBegin + uint64_t(numFATs) * uint64_t(sectorPerFat) * bytesPerSecor;

    // compute total clusters base on image file size
    struct stat st;
    if (fstat(fd, &st) == 0)
    {
        uint64_t totalSectors = st.st_size / bytesPerSecor;
        // Data sectors = Total - Reserved - (NumFATs * SectorsPerFAT)
        uint64_t nonDataSectors = uint64_t(reservedSectors) + uint64_t(numFATs) * uint64_t(sectorPerFat);
        
        if (totalSectors > nonDataSectors)
        {
            uint64_t dataSectors = totalSectors - nonDataSectors;
            totalClusters = uint32_t(dataSectors / sectorPerCluster);
        }
        else
        {
            totalClusters = 0;
        }
    }

    // Sanity checks
    // if (bytesPerSecor == 0 || sectorPerCluster == 0 || sectorPerFat == 0)
    // {
    //     throw runtime_error("Wrong Boot sector contains invalid values");
    //     // Fix this later - HAU
    // }
}

bool FAT32Recovery::fixBootSectorBackup()
{
    uint8_t backupBS[512];
    // Read Backup Boot Sector (Sector 6)
    if (readBytes(6 * 512, backupBS, sizeof(backupBS)) != (ssize_t)sizeof(backupBS))
    {
        cout << "[ERROR] Failed to read Backup Boot Sector for fixing." << endl;
        return false;
    }

    // Validate Backup Boot Sector
    if (!parseAndValidateBootSector(backupBS))
    {
        cout << "[ERROR] Backup Boot Sector is also invalid. Cannot fix." << endl;
        return false;
    }

    // Write Backup Boot Sector to Primary Boot Sector (Sector 0)
    cout << "[INFO] Overwriting Sector 0 with valid Backup from Sector 6..." << endl;
    if (pwrite(fd, backupBS, sizeof(backupBS), 0) != (ssize_t)sizeof(backupBS))
    {
        cout << "[ERROR] Failed to write fixed Boot Sector." << endl;
        return false;
    }
    cout << "[INFO] Successfully fixed Boot Sector." << endl;
    return true;
}

// ================================ FAT TABLE LOADING ===================================
void FAT32Recovery::loadFAT()
{
    uint64_t fatBytes = uint64_t(sectorPerFat) * bytesPerSecor;
    vector<uint8_t> buf(fatBytes);
    ssize_t r = readBytes(fatBegin, buf.data(), buf.size());
    if (r != (ssize_t)buf.size())
    {
        throw runtime_error("Failed to read FAT table");
    }

    size_t entries = buf.size() / 4;
    FAT.assign(entries, 0);
    for (size_t i = 0; i < entries; ++i)
    {
        FAT[i] = read_u32_le(buf.data() + i * 4) & 0x0FFFFFFF; // 28-bit FAT entries
    }
}

// ================================ CLUSTER UTILS =======================================
uint64_t FAT32Recovery::cluster2Offset(uint32_t cluster) const
{
    if (cluster < 2)
    {
        throw runtime_error("Invalid cluster number");
        // Fix this later - HAU
    }

    uint64_t offset = dataBegin + uint64_t(cluster - 2) * sectorPerCluster * bytesPerSecor;
    return offset;
}

void FAT32Recovery::readCluster(uint32_t cluster, vector<uint8_t> &buffer) const
{
    uint64_t off = cluster2Offset(cluster);
    size_t sz = size_t(sectorPerCluster) * bytesPerSecor;
    buffer.resize(sz);
    ssize_t r = readBytes(off, buffer.data(), sz);
    if (r != (ssize_t)sz)
    {
        throw runtime_error("Failed to read cluster " + to_string(cluster));
    }
}

// ================================ RECOVERY FIELDS =====================================
