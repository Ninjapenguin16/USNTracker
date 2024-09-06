#include <stdio.h>
#include <windows.h>
#include <wchar.h>

#define BUFFER_SIZE 4096

// Function to check if a file path starts with a specific folder path
BOOL IsFileInFolder(LPCWSTR filePath, LPCWSTR folderPath) {
    return _wcsnicmp(filePath, folderPath, wcslen(folderPath)) == 0;
}

// Function to resolve the full path of a file
BOOL GetFullPathByFileReference(HANDLE hVol, DWORDLONG fileReferenceNumber, wchar_t *fullPath, DWORD fullPathSize) {
    FILE_ID_DESCRIPTOR fileId = { 0 };
    HANDLE hFile;
    WCHAR tempPath[MAX_PATH];

    // Prepare file ID descriptor
    fileId.dwSize = sizeof(FILE_ID_DESCRIPTOR);
    fileId.Type = FileIdType;
    fileId.FileId.QuadPart = fileReferenceNumber;

    // Open the file by file reference number
    hFile = OpenFileById(hVol, &fileId, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // Get the file path
    if (GetFinalPathNameByHandleW(hFile, tempPath, MAX_PATH, FILE_NAME_NORMALIZED) == 0) {
        CloseHandle(hFile);
        return FALSE;
    }

    // Remove the \\?\ prefix from the path and copy it to the output
    wcsncpy(fullPath, tempPath + 4, fullPathSize - 1);
    fullPath[fullPathSize - 1] = L'\0';

    CloseHandle(hFile);
    return TRUE;
}

// Function to decode and print the event reason
void PrintEventReason(DWORD reason) {

    // This seems stupid and it is but not much of a better way to do it
    if(reason & USN_REASON_FILE_CREATE)
        wprintf(L"  - File created\n");
    if(reason & USN_REASON_FILE_DELETE)
        wprintf(L"  - File deleted\n");
    if(reason & USN_REASON_DATA_OVERWRITE)
        wprintf(L"  - Data overwritten\n");
    if(reason & USN_REASON_DATA_EXTEND)
        wprintf(L"  - Data extended\n");
    if(reason & USN_REASON_DATA_TRUNCATION)
        wprintf(L"  - Data truncated\n");
    if(reason & USN_REASON_RENAME_NEW_NAME)
        wprintf(L"  - Renamed (new name)\n");
    if(reason & USN_REASON_RENAME_OLD_NAME)
        wprintf(L"  - Renamed (old name)\n");
    if(reason & USN_REASON_CLOSE)
        wprintf(L"  - File closed\n");
    if(reason & USN_REASON_SECURITY_CHANGE)
        wprintf(L"  - Security changed\n");
    if(reason & USN_REASON_BASIC_INFO_CHANGE)
        wprintf(L"  - Basic info changed\n");
    if(reason & USN_REASON_EA_CHANGE)
        wprintf(L"  - Extended attributes changed\n");
    if(reason & USN_REASON_INDEXABLE_CHANGE)
        wprintf(L"  - Indexing status changed\n");
    if(reason & USN_REASON_HARD_LINK_CHANGE)
        wprintf(L"  - Hard link changed\n");
    if(reason & USN_REASON_COMPRESSION_CHANGE)
        wprintf(L"  - Compression changed\n");
    if(reason & USN_REASON_ENCRYPTION_CHANGE)
        wprintf(L"  - Encryption changed\n");
    if(reason & USN_REASON_OBJECT_ID_CHANGE)
        wprintf(L"  - Object ID changed\n");
    if(reason & USN_REASON_REPARSE_POINT_CHANGE)
        wprintf(L"  - Reparse point changed\n");
    if(reason & USN_REASON_STREAM_CHANGE)
        wprintf(L"  - Stream changed\n");
}

// Function to print file event message with full path and details
void PrintFileEventMessage(LPCWSTR fullPath, DWORD reason, USN Usn){

    printf("%lld- ", Usn);

    wprintf(L"File: %s\n", fullPath);
    PrintEventReason(reason);
}

int IsRunningAsAdmin(){

    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isAdmin;
}

int RestartAsAdmin(int argc, wchar_t* argv[]){

    // Build the argument list to pass to the elevated instance
    wchar_t commandLine[1024] = { 0 };

    for(int i = 1; i < argc; i++){
        wcscat(commandLine, L"\"");
        wcscat(commandLine, argv[i]);
        wcscat(commandLine, L"\" ");
    }

    // Relaunch the program with admin rights
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";  // Request elevation
    sei.lpFile = argv[0];   // Path to the current executable
    sei.lpParameters = commandLine;  // Pass arguments
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;

    if(!ShellExecuteExW(&sei)){

        DWORD dwError = GetLastError();
        if (dwError == ERROR_CANCELLED)
            MessageBox(NULL, L"This program must be run as admin to work", L"Permissions Error", MB_OK | MB_ICONERROR);
        else
            MessageBox(NULL, L"Failed to elevate despite user allowance", L"Permissions Error", MB_OK | MB_ICONERROR);

        return 1;
    }

    return 0; // Elevated process will restart
}

int wmain(int argc, wchar_t* argv[]) {

    // Make sure program is run as admin
    // and prompt to run as admin if not
    if(!IsRunningAsAdmin())
        return RestartAsAdmin(argc, argv);

    HANDLE hVol = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    BYTE buffer[BUFFER_SIZE] = { 0 };
    USN_JOURNAL_DATA usnJournalData;
    USN lastUsn = 0;

    LPCWSTR targetFolder = L"C:\\";

    // Check for folder path argument
    if(argc >= 2){
        targetFolder = argv[1];
    }

    // Open file pointer to the C drive
    hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (hVol == INVALID_HANDLE_VALUE) {
        printf("Failed to open C drive.\n");
        return 1;
    }

    // Get the USN Journal's properties
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &usnJournalData, sizeof(usnJournalData), &bytesReturned, NULL)) {
        printf("Failed to query USN journal.\n");
        CloseHandle(hVol);
        return 1;
    }

    // Initialize USN value
    lastUsn = usnJournalData.NextUsn;

    // Setup USN Journal monitoring
    READ_USN_JOURNAL_DATA readData = { 0 };
    readData.ReasonMask = USN_REASON_FILE_CREATE | USN_REASON_FILE_DELETE | USN_REASON_DATA_OVERWRITE | USN_REASON_DATA_EXTEND |
                          USN_REASON_DATA_TRUNCATION | USN_REASON_RENAME_NEW_NAME | USN_REASON_RENAME_OLD_NAME |
                          USN_REASON_SECURITY_CHANGE | USN_REASON_BASIC_INFO_CHANGE | USN_REASON_EA_CHANGE |
                          USN_REASON_INDEXABLE_CHANGE | USN_REASON_HARD_LINK_CHANGE | USN_REASON_COMPRESSION_CHANGE |
                          USN_REASON_ENCRYPTION_CHANGE | USN_REASON_OBJECT_ID_CHANGE | USN_REASON_REPARSE_POINT_CHANGE |
                          USN_REASON_STREAM_CHANGE | USN_REASON_CLOSE;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = usnJournalData.UsnJournalID;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;

    while (TRUE) {
        readData.StartUsn = lastUsn;

        // Results in a max of ~800 logs a second
        // Also makes it use a lot less proccessing power
        Sleep(1);

        // Read USN journal
        if (DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData), buffer, BUFFER_SIZE, &bytesReturned, NULL)) {
            USN_RECORD *usnRecord = (USN_RECORD *)&buffer[sizeof(USN)];
            while ((BYTE *)usnRecord < buffer + bytesReturned) {
                wchar_t fullPath[MAX_PATH];

                // Resolve the full path
                if (GetFullPathByFileReference(hVol, usnRecord->FileReferenceNumber, fullPath, MAX_PATH)) {
                    // Check if the file is in the specified folder
                    if (IsFileInFolder(fullPath, targetFolder)) {
                        // Print event message if the file is in the target folder
                        PrintFileEventMessage(fullPath, usnRecord->Reason, usnRecord->Usn);
                    }
                }

                // Update last processed USN
                lastUsn = usnRecord->Usn + usnRecord->RecordLength;

                // Move to the next USN record
                usnRecord = (USN_RECORD *)((PBYTE)usnRecord + usnRecord->RecordLength);
            }
        } else {
            printf("Failed to read USN journal.\n");
            break;
        }
    }

    // Clean up
    CloseHandle(hVol);
    return 0;
}
