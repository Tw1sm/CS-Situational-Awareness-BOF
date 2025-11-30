#include <windows.h>
#include <lm.h>
#include <dsgetdc.h>
#include "bofdefs.h"
#include "base.c"


BOOL FileExists(char* filePath) {
    DWORD attrib = KERNEL32$GetFileAttributesA(filePath);
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Read file and convert to ASCII string (handles UTF-16)
char* ReadFileAsString(char* filePath, DWORD* outSize) {
    HANDLE hFile = KERNEL32$CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    DWORD fileSize = KERNEL32$GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    // Limit file size to prevent memory issues (max 1MB)
    if (fileSize > 1048576) {
        internal_printf("  [!] File too large (%lu bytes), skipping: %s\n", fileSize, filePath);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    char* buffer = (char*)intAlloc(fileSize + 2);
    if (buffer == NULL) {
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    DWORD bytesRead = 0;
    if (!KERNEL32$ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        intFree(buffer);
        KERNEL32$CloseHandle(hFile);
        return NULL;
    }

    KERNEL32$CloseHandle(hFile);

    // Check for UTF-16 LE BOM
    BOOL isUtf16 = FALSE;
    if (bytesRead >= 2 && (unsigned char)buffer[0] == 0xFF && (unsigned char)buffer[1] == 0xFE) {
        isUtf16 = TRUE;
    }

    char* result = NULL;
    if (isUtf16) {
        // Convert UTF-16 LE to ASCII/UTF-8
        wchar_t* wideBuffer = (wchar_t*)buffer;
        int wideLen = bytesRead / 2;

        // Skip BOM if present
        int startIdx = 0;
        if (bytesRead >= 2 && (unsigned char)buffer[0] == 0xFF && (unsigned char)buffer[1] == 0xFE) {
            startIdx = 1;
            wideLen--;
        }

        // Convert to multibyte
        int mbLen = Kernel32$WideCharToMultiByte(CP_ACP, 0, &wideBuffer[startIdx], wideLen, NULL, 0, NULL, NULL);
        if (mbLen > 0) {
            result = (char*)intAlloc(mbLen + 1);
            if (result) {
                Kernel32$WideCharToMultiByte(CP_ACP, 0, &wideBuffer[startIdx], wideLen, result, mbLen, NULL, NULL);
                result[mbLen] = '\0';
                if (outSize) *outSize = mbLen;
            }
        }
        intFree(buffer);
    } else {
        // ASCII/UTF-8 file
        buffer[bytesRead] = '\0';
        if (outSize) *outSize = bytesRead;
        result = buffer;
    }

    return result;
}

// Check if GptTmpl.inf contains group membership modifications
BOOL HasGroupMembership(char* content) {
    if (content == NULL) return FALSE;

    // Look for [Group Membership] section
    char* ptr = MSVCRT$strstr(content, "[Group Membership]");
    return (ptr != NULL);
}

// Print bofhound result window
void PrintGpoGroup(char* domain, char* gpoGuid, char* content) {
    internal_printf("-----------GPO Group-----------\n");
    internal_printf("Domain: %s\n", domain);
    internal_printf("GPO Name: %s\n", gpoGuid);
    internal_printf("Content:\n%s\n", content);
    internal_printf("-----------End GPO Group-----------\n\n");
}

BOOL CheckGpoFiles(char* sysvolPath, char* gpoGuid, char* domain) {
    char machinePath[MAX_PATH * 2];
    char groupsXmlPath[MAX_PATH * 2];
    char gptTmplPath[MAX_PATH * 2];
    BOOL foundGroupInfo = FALSE;

    // Construct paths for Machine and User policies
    MSVCRT$sprintf(machinePath, "%s\\%s\\Machine", sysvolPath, gpoGuid);

    // Check for Groups.xml in Machine\Preferences\Groups
    MSVCRT$sprintf(groupsXmlPath, "%s\\Preferences\\Groups\\Groups.xml", machinePath);
    if (FileExists(groupsXmlPath)) {
        DWORD size = 0;
        char* content = ReadFileAsString(groupsXmlPath, &size);
        if (content != NULL) {
            PrintGpoGroup(domain, gpoGuid, content);
            intFree(content);
            foundGroupInfo = TRUE;
        }
    }

    // Check for GptTmpl.inf in Machine\Microsoft\Windows NT\SecEdit
    MSVCRT$sprintf(gptTmplPath, "%s\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf", machinePath);
    if (FileExists(gptTmplPath)) {
        DWORD size = 0;
        char* content = ReadFileAsString(gptTmplPath, &size);
        if (content != NULL) {
            if (HasGroupMembership(content)) {
                PrintGpoGroup(domain, gpoGuid, content);
                foundGroupInfo = TRUE;
            }
            intFree(content);
        }
    }

    return foundGroupInfo;
}

void EnumerateGpos(char* sysvolPath, char* domain) {
    WIN32_FIND_DATA findData;
    char searchPath[MAX_PATH * 2];
    HANDLE hFind = NULL;
    int gpoCount = 0;

    MSVCRT$sprintf(searchPath, "%s\\{*", sysvolPath);

    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        internal_printf("[!] Failed to enumerate GPOs in SYSVOL: %lu\n", KERNEL32$GetLastError());
        return;
    }

    // First pass - count GPOs
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MSVCRT$strcmp(findData.cFileName, ".") != 0 &&
                MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                int len = MSVCRT$strlen(findData.cFileName);
                if (len > 2 && findData.cFileName[0] == '{' && findData.cFileName[len-1] == '}') {
                    gpoCount++;
                }
            }
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);

    internal_printf("[*] Found %d GPO(s) to check\n\n", gpoCount);

    if (gpoCount == 0) {
        return;
    }

    // Second pass - process GPOs
    hFind = KERNEL32$FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (MSVCRT$strcmp(findData.cFileName, ".") != 0 &&
                MSVCRT$strcmp(findData.cFileName, "..") != 0) {
                int len = MSVCRT$strlen(findData.cFileName);
                if (len > 2 && findData.cFileName[0] == '{' && findData.cFileName[len-1] == '}') {
                    CheckGpoFiles(sysvolPath, findData.cFileName, domain);
                }
            }
        }
    } while (KERNEL32$FindNextFileA(hFind, &findData));

    KERNEL32$FindClose(hFind);
}

void NetGPOGroup(char* gpoName, char* domainName) {
    PDOMAIN_CONTROLLER_INFOA dcInfo = NULL;
    char sysvolPath[MAX_PATH * 2];
    DWORD result;

    // Get domain controller
    if (domainName == NULL || MSVCRT$strlen(domainName) == 0) {
        internal_printf("[*] Using current domain\n");
        result = NETAPI32$DsGetDcNameA(NULL, NULL, NULL, NULL, 0, &dcInfo);
    } else {
        internal_printf("[*] Using domain: %s\n", domainName);
        result = NETAPI32$DsGetDcNameA(NULL, domainName, NULL, NULL, 0, &dcInfo);
    }

    if (result != ERROR_SUCCESS) {
        internal_printf("[!] Failed to get domain controller: %lu\n", result);
        return;
    }

    internal_printf("[+] Domain Controller: %s\n", dcInfo->DomainControllerName);
    internal_printf("[+] Domain Name: %s\n", dcInfo->DomainName);

    // Extract DC name (remove leading \\)
    char* dcName = dcInfo->DomainControllerName;
    if (dcName[0] == '\\' && dcName[1] == '\\') {
        dcName += 2;
    }

    // Construct SYSVOL path
    MSVCRT$sprintf(sysvolPath, "\\\\%s\\SYSVOL\\%s\\Policies", dcName, dcInfo->DomainName);
    internal_printf("[*] SYSVOL Path: %s\n\n", sysvolPath);

    if (gpoName == NULL || MSVCRT$strlen(gpoName) == 0 ||
        MSVCRT$_stricmp(gpoName, "all") == 0) {
        EnumerateGpos(sysvolPath, dcInfo->DomainName);
    } else {
        // Single GPO, check {}
        char gpoGuid[256];
        if (gpoName[0] == '{') {
            MSVCRT$strcpy(gpoGuid, gpoName);
        } else {
            MSVCRT$sprintf(gpoGuid, "{%s}", gpoName);
        }

        BOOL found = CheckGpoFiles(sysvolPath, gpoGuid, dcInfo->DomainName);
        if (!found) {
            internal_printf("[*] No group membership information found in GPO %s\n", gpoGuid);
        }
    }

    NETAPI32$NetApiBufferFree(dcInfo);
}

#ifdef BOF
VOID go(
    IN PCHAR Buffer,
    IN ULONG Length
)
{
    datap parser = {0};
    char* gpoName = NULL;
    char* domainName = NULL;

    if (!bofstart()) {
        return;
    }

    // Parse arguments
    BeaconDataParse(&parser, Buffer, Length);
    gpoName = BeaconDataExtract(&parser, NULL);
    domainName = BeaconDataExtract(&parser, NULL);

    // Default to "all" if gpoName is empty
    if (gpoName == NULL || MSVCRT$strlen(gpoName) == 0) {
        gpoName = "all";
    }

    NetGPOGroup(gpoName, domainName);

    printoutput(TRUE);
}

#else

int main()
{
    NetGPOGroup("all", NULL);
    return 0;
}

#endif
