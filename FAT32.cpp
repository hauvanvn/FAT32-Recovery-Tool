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
}

bool DirEntry::isLFN() const
{
}

bool DirEntry::isdDir() const
{
}

uint32_t DirEntry::getStartCluster() const
{
}

// ================================ CONSTRUCT/DECONTRUCT ================================
FAT32Recovery::FAT32Recovery(const string &path) : imagePath(path)
{
    fd = -1;
    bytesPerSecor = 0;
    sectorPerCluster = 0;
    reservedSectors = 0;
    numFATs = 0;
    secotrPerFat = 0;
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

// ================================ BOOT SECTOR PARSER ==================================

// ================================ FAT TABLE LOADING ===================================

// ================================ CLUSTER UTILS =======================================

// ================================ RECOVERY FIELDS =====================================
