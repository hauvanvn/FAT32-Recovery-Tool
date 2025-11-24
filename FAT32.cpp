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

    fd = open(imagePath.c_str(), O_RDONLY);
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
void FAT32Recovery::readBootSector()
{
    uint8_t bs[512];
    ssize_t r = readBytes(0, bs, sizeof(bs));
    if (r != (ssize_t)sizeof(bs))
    {
        throw runtime_error("Failed toread boot sector");
    }

    bytesPerSecor = read_u16_le(bs + 11);
    sectorPerCluster = bs[13];
    reservedSectors = read_u16_le(bs + 14);
    numFATs = bs[16];
    sectorPerCluster = read_u32_le(bs + 36);
    rootCluster = read_u32_le(bs + 44);

    // compute offsets
    fatBegin = uint32_t(uint64_t(reservedSectors) * bytesPerSecor);
    dataBegin = fatBegin + uint64_t(numFATs) * sectorPerFat * bytesPerSecor;

    // compute total clusters base on image file size
    struct stat st;
    if (fstat(fd, &st) == 0)
    {
        uint64_t totalSectors = st.st_size / bytesPerSecor;
        uint64_t dataSectors = totalSectors - (reservedSectors + uint64_t(numFATs) * sectorPerFat);
        totalClusters = uint32_t(dataSectors / sectorPerCluster);
    }
    else
    {
        totalClusters = 0;
    }

    // Sanity checks
    if (bytesPerSecor == 0 || sectorPerCluster == 0 || sectorPerFat == 0)
    {
        throw runtime_error("Wrong Boot sector contains invalid values");
        // Fix this later - HAU
    }
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
