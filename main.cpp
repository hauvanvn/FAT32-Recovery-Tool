#include "FAT32.h"

string filepath = "USB200MB.vhd";

int main()
{
    FAT32Recovery disk(filepath);
    cout << "Hello World!\n";
    return 0;
}