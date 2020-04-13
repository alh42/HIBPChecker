// HIBPChecker.cpp
// 
// Check a database downloaded from https://haveibeenpwned.com/Passwords for if a password is leaked
//

#include <Windows.h>
#include <Memoryapi.h>
#include <bcrypt.h>

#include <iostream>

#define PASSWORD_TO_CHECK "password"
#define PASSWORD_FILE "pwned-passwords-sha1-ordered-by-hash-v5.txt"

const SIZE_T MapRegionSize = 128 * 1024 * 1024;

CHAR* GetEntryScanBackward(SIZE_T* entrySize, LPVOID base)
{
  CHAR* entryEnd = (CHAR*)base;
  while (*entryEnd != '\r') --entryEnd;
  CHAR* entryStart = --entryEnd;
  while (*entryStart != '\n') --entryStart;
  ++entryStart;
  *entrySize = entryEnd - entryStart;
  return entryStart;
}

const CHAR* table = "0123456789ABCDEF";

void ValToHex(CHAR* output, int val)
{
  *(output + 1) = table[val & 0xf];
  val >>= 4;
  *(output) = table[val & 0xf];
}

CHAR* CreateHash(CONST CHAR* data, SIZE_T dataLength)
{
  BCRYPT_ALG_HANDLE algHandle;
  NTSTATUS stat = BCryptOpenAlgorithmProvider(&algHandle, BCRYPT_SHA1_ALGORITHM, NULL, 0);

  ULONG result;
  DWORD hashLength = 0;
  stat = BCryptGetProperty(algHandle, BCRYPT_HASH_LENGTH, (UCHAR*)&hashLength, sizeof(DWORD), &result, 0);

  UCHAR hashBuf[64] = { 0 };
  stat = BCryptHash(algHandle, NULL, 0, (UCHAR*)data, dataLength, hashBuf, hashLength);

  CHAR* hashedString = (CHAR*)malloc(hashLength * 2 + 1);
  for (int i = 0; i < hashLength; ++i) {
    ValToHex(hashedString + i * 2, hashBuf[i]);
  }
  hashedString[hashLength * 2] = 0;
  return hashedString;
}

CHAR* GetCount(CHAR* entry)
{
  entry += 41;
  CHAR* entryEnd = entry;
  while (*entryEnd != '\r') entryEnd++;
  SIZE_T size = entryEnd - entry;
  CHAR* result = (CHAR*)malloc(size);
  memcpy(result, entry, size);
  result[size] = 0;
  return result;
}

bool FindEntry(CHAR* firstEntry, CHAR* end, CHAR* hash)
{
  while (firstEntry + 64 <= end && strncmp(firstEntry, hash, 40) != 0) {
    firstEntry += 40;
    while (*firstEntry != '\n') ++firstEntry;
    ++firstEntry;
  }
  if (strncmp(firstEntry, hash, 40) == 0) {
    // Match!
    printf("Found it! %s times used", GetCount(firstEntry));
    return true;
  }
  return false;
}

int main(int argc, TCHAR* argv[])
{
  CHAR* hash = CreateHash(PASSWORD_TO_CHECK, strlen(PASSWORD_TO_CHECK));

  printf("Checking Password \"%s\", With hash %s\n\n", PASSWORD_TO_CHECK, hash);

  HANDLE fileHandle = CreateFileA(PASSWORD_FILE, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
  if (INVALID_HANDLE_VALUE == fileHandle) {
    printf("Failed to open passwords file!");
    return -1;
  }

  DWORD fileSizeHigh = 0;
  DWORD fileSizeLow = GetFileSize(fileHandle, &fileSizeHigh);

  uint64_t fileSizeRemaining = (((uint64_t)fileSizeHigh) << 32) + fileSizeLow;

  HANDLE mappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, "pwmapping");

  SYSTEM_INFO sysInfo;
  GetSystemInfo(&sysInfo);

  uint64_t offset = 0;
  DWORD low = 0;
  DWORD high = 0;
  CHAR* firstEntry = NULL;
  SIZE_T firstEntrySize = 0;
  CHAR* lastEntry = NULL;
  SIZE_T lastEntrySize = 0;
  LPVOID base = NULL;
  while (base = MapViewOfFile(mappingHandle, FILE_MAP_READ, high, low, MapRegionSize)) {
    lastEntry = GetEntryScanBackward(&lastEntrySize, (CHAR*)base + MapRegionSize - 1);
    if (strncmp(lastEntry, hash, 40) >= 0) {
      // It might be in this block, look for it!
      CHAR* firstEntry = (CHAR*)base;
      if (offset > 0) {
        while (*firstEntry != '\n') ++firstEntry;
        ++firstEntry;
      }
      bool found = FindEntry(firstEntry, (CHAR*)base + MapRegionSize, hash);
      if (found) {
        UnmapViewOfFile(base);
        return 0;
      }
    }
    UnmapViewOfFile(base);
    offset += (MapRegionSize - sysInfo.dwAllocationGranularity);
    high = (offset & 0xffffffff00000000) >> 32;
    low = (offset & 0xffffffff);
    fileSizeRemaining -= (MapRegionSize - sysInfo.dwAllocationGranularity);
  }
  //    if (base == NULL) {
  //      DWORD err = GetLastError();
  //      printf("error! %d", err);
  //    }

      // Check last block.
  if (base = MapViewOfFile(mappingHandle, FILE_MAP_READ, high, low, 0)) {
    bool found = FindEntry((CHAR*)base, (CHAR*)base + fileSizeRemaining, hash);
    UnmapViewOfFile(base);
    if (found) {
      return 0;
    }
  }

  printf("Not found!");
  return 0;
}
