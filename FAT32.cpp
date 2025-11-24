#include "FAT32.h"

#include <fcntl.h>
#include <unistd.h>
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

    // fd = open(imagePath.c_str(), O_RDONLY);
    fd = open(imagePath.c_str(), O_RDWR);
    if (fd < 0)
        throw runtime_error(string("Open failed: ") + strerror(errno));

    readBootSector();
    loadFAT();
}

FAT32Recovery::~FAT32Recovery()
{
    if (fd >= 0)
        close(fd);
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
    ssize_t r = pread(fd, buf, size, offset);
    return (r < 0 ? -1 : r);
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

// ======================================================================
//                       BOOT SECTOR PARSING / VALIDATION
// ======================================================================
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
    if (temp_bytesPerSector == 0 || (temp_bytesPerSector % 512) != 0)
        return false;
    // Sector per cluster should be power of 2 and <= 128
    if (temp_sectorPerCluster == 0 || temp_sectorPerCluster > 128 || (temp_sectorPerCluster & (temp_sectorPerCluster - 1)) != 0)
        return false;
    // Reserved sectors should be at least 1
    if (temp_reservedSectors < 1)
        return false;
    // Number of FATs should be 1 or 2
    if (temp_numFATs < 1 || temp_numFATs > 2)
        return false;
    // Sector per FAT should be non-zero
    if (temp_sectorPerFat == 0)
        return false;
    // Root cluster should be at least 2
    if (temp_rootCluster < 2)
        return false;

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

// ======================================================================
//                        FAT TABLE LOAD / WRITE
// ======================================================================
void FAT32Recovery::loadFAT()
{
    uint64_t fatBytes = uint64_t(sectorPerFat) * bytesPerSecor;

    vector<uint8_t> buf(fatBytes);
    if (readBytes(fatBegin, buf.data(), buf.size()) != (ssize_t)buf.size())
        throw runtime_error("Failed to read FAT");

    size_t entries = buf.size() / 4;
    FAT.assign(entries, 0);

    for (size_t i = 0; i < entries; ++i)
        FAT[i] = read_u32_le(&buf[i * 4]) & 0x0FFFFFFF;
}

void FAT32Recovery::writeFAT2Disk()
{
    if (FAT.empty())
        throw runtime_error("No FAT loaded");

    vector<uint8_t> buf(FAT.size() * 4);

    for (size_t i = 0; i < FAT.size(); ++i)
    {
        uint32_t v = FAT[i] & 0x0FFFFFFF;
        buf[i * 4 + 0] = (v & 0xFF);
        buf[i * 4 + 1] = (v >> 8);
        buf[i * 4 + 2] = (v >> 16);
        buf[i * 4 + 3] = (v >> 24);
    }

    for (uint8_t i = 0; i < numFATs; ++i)
    {
        uint64_t off = fatBegin + uint64_t(i) * sectorPerFat * bytesPerSecor;
        if (pwrite(fd, buf.data(), buf.size(), off) != (ssize_t)buf.size())
            throw runtime_error("Failed to write FAT");
    }

    fsync(fd);
    cout << "[INFO] FAT updated.\n";
}

// ======================================================================
//                         CLUSTER UTILITIES
// ======================================================================
uint64_t FAT32Recovery::cluster2Offset(uint32_t cluster) const
{
    if (cluster < 2)
        throw runtime_error("Invalid cluster number");

    return dataBegin + uint64_t(cluster - 2) * sectorPerCluster * bytesPerSecor;
}

void FAT32Recovery::readCluster(uint32_t cluster, vector<uint8_t> &buffer) const
{
    uint64_t off = cluster2Offset(cluster);
    size_t size = sectorPerCluster * bytesPerSecor;

    buffer.resize(size);
    ssize_t r = readBytes(off, buffer.data(), size);

    if (r != (ssize_t)size)
        throw runtime_error("Failed to read cluster");
}

// ======================================================================
//                         VALIDATE & FIX FUNCTIONS
// ======================================================================
bool FAT32Recovery::validateAndFixMBR(uint32_t partitionID, bool doFix)
{
    // READ MBR
    const uint16_t mbrBytes = 512;
    vector<uint8_t> mbr(mbrBytes);
    if (readBytes(0, mbr.data(), mbr.size()) != (ssize_t)mbr.size())
    {
        cout << "Failed to read MBR\n";
        return false;
    }

    // check MBR signature 0x55AA
    if (mbr[510] != 0x55 || mbr[511] != 0xAA)
    {
        cout << "MBR signature missing\n";
    }

    if (partitionID >= 4)
        return false;
    size_t partEntryOff = 0x1BE + partitionID * 16;
    uint8_t *pe = mbr.data() + partEntryOff;

    // Partition starting LBA
    uint32_t partStartLBA = uint32_t(pe[8]) | (uint32_t(pe[9]) << 8) | (uint32_t(pe[10]) << 16) | (uint32_t(pe[11]) << 24);
    uint32_t parType = pe[4];

    // Find where our boot sector actually sits:
    // We consider boot sector at offset 0 in current implementation (image may be partition image).
    // But if image is full-disk, real boot is at partStartLBA * bytesPerSector.
    // Let's detect: check for 0x55AA at offset partStartLBA*bytesPerSector, and also check our bootsector signature at offset 11..12 (bytes per sector value).
    // Read boot candidate at LBA = partStartLBA
    std::vector<uint8_t> bs(bytesPerSecor); // bytesPerSecor available only if we've already parsed boot sector; but this function may be called early.
    // So we'll read 512 bytes and inspect 0x55AA
    std::vector<uint8_t> candidate(512);
    uint64_t candidateOff = uint64_t(partStartLBA) * 512ULL;
    if (pread(fd, candidate.data(), candidate.size(), candidateOff) != (ssize_t)candidate.size())
    {
        // cannot read candidate (maybe startLBA outside file): treat as invalid
        cerr << "validateAndFixMBR: cannot read candidate boot at partition LBA " << partStartLBA << "\n";
    }
    else
    {
        bool sig = (candidate[510] == 0x55 && candidate[511] == 0xAA);
        if (!sig)
        {
            cerr << "validateAndFixMBR: partition entry points to LBA " << partStartLBA << " but no boot signature there.\n";
        }
        else
        {
            // Good: partition entry matches a boot sector.
            cout << "validateAndFixMBR: partition " << partitionID << " points to a valid boot sector.\n";
        }
    }

    // Heuristic: if the boot sector used by our parser (the one read at offset 0) looks like FAT32 (we have bytesPerSecor etc),
    // but partition table points elsewhere, propose to update partition entry to 0.
    // Check current boot sector at LBA 0 too:
    bool bootAtZeroIsFAT = false;
    {
        std::vector<uint8_t> b0(512);
        if (pread(fd, b0.data(), b0.size(), 0) == (ssize_t)b0.size())
        {
            // check 0x55AA and BPB signature plausibility (bytes per sector non-zero)
            if (b0[510] == 0x55 && b0[511] == 0xAA)
            {
                uint16_t bps = uint16_t(b0[11]) | (uint16_t(b0[12]) << 8);
                uint8_t spc = b0[13];
                if (bps == bytesPerSecor && spc == sectorPerCluster)
                {
                    bootAtZeroIsFAT = true;
                }
                else if (bps == 512)
                {
                    // not strictly equal but plausible
                    bootAtZeroIsFAT = true;
                }
            }
        }
    }

    if (bootAtZeroIsFAT && partStartLBA != 0)
    {
        cerr << "validateAndFixMBR: detected mismatch: image contains a FAT boot at LBA 0, but MBR partition points to LBA " << partStartLBA << "\n";
        if (doFix)
        {
            // Patch partition start LBA to 0 and write MBR back
            uint32_t newStart = 0;
            pe[8] = (newStart & 0xFF);
            pe[9] = ((newStart >> 8) & 0xFF);
            pe[10] = ((newStart >> 16) & 0xFF);
            pe[11] = ((newStart >> 24) & 0xFF);
            // write MBR back
            if (pwrite(fd, mbr.data(), mbr.size(), 0) != (ssize_t)mbr.size())
            {
                cerr << "validateAndFixMBR: failed to write MBR patch: " << strerror(errno) << "\n";
                return false;
            }
            cout << "validateAndFixMBR: patched partition " << partitionID << " start LBA -> 0\n";
        }
        else
        {
            cout << "validateAndFixMBR: call with doFix=true to auto-patch MBR partition start to 0\n";
        }
    }

    return true;
}

// ======================================================================
//                      FAT CONSISTENCY CHECK & REPAIR
// ======================================================================
void FAT32Recovery::buildUsedClustersFromDirectories(set<uint32_t> &used)
{
    // traverse directory tree starting from rootCluster
    // naive stack-based traversal without LFN reconstruction
    vector<uint32_t> stack;
    stack.push_back(rootCluster);

    while (!stack.empty())
    {
        uint32_t cl = stack.back();
        stack.pop_back();
        // read directory clusters chain (use followFAT)
        vector<uint32_t> dirChain = followFAT(cl);
        if (dirChain.empty())
            dirChain.push_back(cl);

        vector<uint8_t> buf;
        for (uint32_t c : dirChain)
        {
            readCluster(c, buf);
            // read 32-byte entries
            for (size_t off = 0; off + 32 <= buf.size(); off += 32)
            {
                DirEntry de;
                memcpy(&de, buf.data() + off, 32);
                if (de.name[0] == 0x00)
                    break; // end
                if (de.isLFN())
                    continue;
                if (de.isDeleted())
                    continue;
                uint32_t start = de.getStartCluster();
                if (start >= 2 && start < 2 + totalClusters)
                {
                    // follow file cluster chain (best-effort using FAT)
                    vector<uint32_t> fileChain = followFAT(start);
                    if (fileChain.empty())
                    {
                        // even if no FAT, assume at least start cluster belongs
                        used.insert(start);
                    }
                    else
                    {
                        for (uint32_t fc : fileChain)
                            used.insert(fc);
                    }
                }
                // if dir, push to stack
                if (de.isdDir())
                {
                    string s = formatShortName(de.name);
                    if (s != "." && s != ".." && de.getStartCluster() >= 2)
                    {
                        stack.push_back(de.getStartCluster());
                    }
                }
            }
        }
    }
}

void FAT32Recovery::fixFATConsistency(bool doWriteBack)
{
    // Build used set from directory references
    set<uint32_t> used;
    buildUsedClustersFromDirectories(used);

    // Build set of clusters marked used in FAT
    set<uint32_t> fatUsed;
    for (uint32_t i = 2; i < FAT.size(); ++i)
    {
        uint32_t v = FAT[i];
        if (v != 0)
            fatUsed.insert(i);
    }

    // Orphan clusters: in FAT used but not referenced -> mark free
    vector<uint32_t> orphan;
    for (uint32_t c : fatUsed)
    {
        if (!(used.count(c)))
            orphan.push_back(c);
    }

    // Missing clusters: referenced by directory but FAT shows 0 -> we'll try to allocate chains by marking EOC for single cluster,
    // or if consecutive clusters are free, attempt to create contiguous chain using contiguousGuess heuristic.
    vector<uint32_t> missing;
    for (uint32_t c : used)
    {
        if (c < FAT.size() && FAT[c] == 0)
            missing.push_back(c);
    }

    cout << "fixFATConsistency: used clusters from directories = " << used.size()
         << ", clusters marked used in FAT = " << fatUsed.size()
         << ", orphan clusters = " << orphan.size()
         << ", missing clusters = " << missing.size() << "\n";

    // Handle orphans: mark cluster and its chain free (set to 0)
    for (uint32_t c : orphan)
    {
        // follow chain starting from c and clear entries
        uint32_t cur = c;
        while (cur < FAT.size() && FAT[cur] != 0)
        {
            uint32_t nxt = FAT[cur];
            FAT[cur] = 0;
            if (nxt >= 0x0FFFFFF8)
                break;
            if (nxt == 0)
                break;
            if (nxt == cur)
                break;
            cur = nxt;
        }
    }

    // Handle missing: for each missing start cluster, if possible mark it as EOC (single cluster) so file will be readable for that one cluster.
    // If you want, you can attempt contiguous allocation: here we only mark single-cluster EOC to be safe.
    for (uint32_t c : missing)
    {
        if (c < FAT.size())
        {
            FAT[c] = 0x0FFFFFFF; // mark EOC for single cluster
        }
    }

    // Optionally write FAT back
    if (doWriteBack)
    {
        writeFAT2Disk();
        cout << "fixFATConsistency: FAT written back to disk\n";
    }
    else
    {
        cout << "fixFATConsistency: FAT modified in memory but not written. Call with doWriteBack=true to persist.\n";
    }
}

// ======================================================================
//                              END OF FILE
// ======================================================================
