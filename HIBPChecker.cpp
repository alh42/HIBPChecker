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

  UCHAR* hashBuf = (UCHAR*)malloc(hashLength);
  stat = BCryptHash(algHandle, NULL, 0, (UCHAR*)data, dataLength, hashBuf, hashLength);

  BCryptCloseAlgorithmProvider(algHandle, 0);

  CHAR* hashedString = (CHAR*)malloc(hashLength * 2 + 1);
  for (int i = 0; i < hashLength; ++i) {
    ValToHex(hashedString + i * 2, hashBuf[i]);
  }
  free((void*)hashBuf);
  hashedString[hashLength * 2] = 0;
  return hashedString;
}

CHAR* GetCount(CHAR* entry)
{
  entry += 41;
  CHAR* entryEnd = entry;
  while (*entryEnd != '\r') entryEnd++;
  SIZE_T size = entryEnd - entry;
  CHAR* result = (CHAR*)malloc(size + 1);
  memcpy(result, entry, size);
  result[size] = 0;
  return result;
}

bool FindEntry(CHAR* firstEntry, CHAR* end, const CHAR* hash)
{
  while (firstEntry < end && strncmp(firstEntry, hash, 40) != 0) {
    firstEntry += 40;
    while (*firstEntry != '\n') ++firstEntry;
    ++firstEntry;
  }
  if (firstEntry < end) {
    // Match!
    const CHAR* count = GetCount(firstEntry);
    fprintf(stdout,"Found it! leaked %s times", count);
    free((void*)count);
    return true;
  }
  fprintf(stdout, "Not found!");
  return false;
}

int main(int argc, TCHAR* argv[])
{
  const CHAR* password = PASSWORD_TO_CHECK;
  const CHAR* hibpPasswordsFile = PASSWORD_FILE;

  if (argc == 2) {
    password = argv[1];
  }
  if (argc >= 3) {
    hibpPasswordsFile = argv[1];
    password = argv[2];
  }

  HANDLE fileHandle = CreateFileA(hibpPasswordsFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, NULL);
  if (INVALID_HANDLE_VALUE == fileHandle) {
    fprintf(stderr,"Failed to open passwords file %s!",hibpPasswordsFile);
    return -1;
  }

  DWORD fileSizeHigh = 0;
  DWORD fileSizeLow = GetFileSize(fileHandle, &fileSizeHigh);
  uint64_t fileSizeRemaining = (((uint64_t)fileSizeHigh) << 32) + fileSizeLow;

  HANDLE mappingHandle = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, "pwmapping");
  if (INVALID_HANDLE_VALUE == mappingHandle)
  {
    fprintf(stderr, "Failed to create file mapping for %s!", hibpPasswordsFile);
    CloseHandle(fileHandle);
    return -1;
  }

  const CHAR* hash = CreateHash(password, strlen(password));

  fprintf(stdout, "Checking Password \"%s\" with hash %s\n\n", password, hash);


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
      FindEntry(firstEntry, (CHAR*)base + MapRegionSize - 64, hash);
      goto QUIT;
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
  }

QUIT:
  CloseHandle(mappingHandle);
  CloseHandle(fileHandle);
  free((void*)hash);
  return 0;
}
