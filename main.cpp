#include "FAT32.h"

string filepath = "VHDFAT32.vhd";

int main()
{
    FAT32Recovery disk(filepath);

    disk.readMBR();
    disk.listPartition();
    disk.readBootSector(0);
    disk.loadFAT();

    cout << "Hello World!\n";
    return 0;
}