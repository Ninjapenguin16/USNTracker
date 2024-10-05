#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wchar.h>
#include <signal.h>

#define BUFFER_SIZE 4096

HANDLE OutputCSV;

// Function to check if a file path starts with a specific folder path
BOOL IsFileInFolder(LPCWSTR filePath, LPCWSTR folderPath){
    return _wcsnicmp(filePath, folderPath, wcslen(folderPath)) == 0;
}

// Function to check if a file / folder path starts with a specific folder path
BOOL IsInFolder(LPCWSTR filePath, LPCWSTR blacklist){

    size_t fileLen = wcslen(filePath);
    size_t blackLen = wcslen(blacklist);

    if(blackLen > fileLen)
        return 0;

    for(size_t i = 0; i < blackLen; i++)
        if(filePath[i] != blacklist[i])
            return 0;
    
    return 1;
}

BOOL WriteWideStringAsUTF8(const wchar_t *str){
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL);
    if (utf8Size == 0){
        return FALSE;
    }

    char *utf8Str = (char *)malloc(utf8Size);
    if(utf8Str == NULL){
        return FALSE;
    }

    WideCharToMultiByte(CP_UTF8, 0, str, -1, utf8Str, utf8Size, NULL, NULL);

    DWORD bytesWritten;
    BOOL result = WriteFile(OutputCSV, utf8Str, utf8Size - 1, &bytesWritten, NULL);
    free(utf8Str);

    return result;
}

// Function to resolve the full path of a file
BOOL GetFullPathByFileReference(HANDLE hVol, DWORDLONG fileReferenceNumber, wchar_t *fullPath, DWORD fullPathSize){
    FILE_ID_DESCRIPTOR fileId = { 0 };
    HANDLE hFile;
    WCHAR tempPath[MAX_PATH];

    // Prepare file ID descriptor
    fileId.dwSize = sizeof(FILE_ID_DESCRIPTOR);
    fileId.Type = FileIdType;
    fileId.FileId.QuadPart = fileReferenceNumber;

    // Open the file by file reference number
    hFile = OpenFileById(hVol, &fileId, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, 0);
    if(hFile == INVALID_HANDLE_VALUE){
        return FALSE;
    }

    // Get the file path
    if(GetFinalPathNameByHandleW(hFile, tempPath, MAX_PATH, FILE_NAME_NORMALIZED) == 0){
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
void PrintEventReason(DWORD reason, wchar_t *EventReasons){

    int FirstReason = 1;

    // This seems stupid and it is but not much of a better way to do it
    if(reason & USN_REASON_FILE_CREATE){
        wprintf(L"  - File created\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"File created");
    }
    if(reason & USN_REASON_FILE_DELETE){
        wprintf(L"  - File deleted\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"File deleted");
    }
    if(reason & USN_REASON_DATA_OVERWRITE){
        wprintf(L"  - Data overwritten\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Data overwritten");
    }
    if(reason & USN_REASON_DATA_EXTEND){
        wprintf(L"  - Data extended\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Data extended");
    }
    if(reason & USN_REASON_DATA_TRUNCATION){
        wprintf(L"  - Data truncated\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Data truncated");
    }
    if(reason & USN_REASON_RENAME_NEW_NAME){
        wprintf(L"  - Renamed (new name)\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Renamed (new name");
    }
    if(reason & USN_REASON_RENAME_OLD_NAME){
        wprintf(L"  - Renamed (old name)\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Renamed (old name)");
    }
    if(reason & USN_REASON_CLOSE){
        wprintf(L"  - File closed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"File closed");
    }
    if(reason & USN_REASON_SECURITY_CHANGE){
        wprintf(L"  - Security changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Security changed");
    }
    if(reason & USN_REASON_BASIC_INFO_CHANGE){
        wprintf(L"  - Basic info changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Basic info changed");
    }
    if(reason & USN_REASON_EA_CHANGE){
        wprintf(L"  - Extended attributes changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Extended attributes changed");
    }
    if(reason & USN_REASON_INDEXABLE_CHANGE){
        wprintf(L"  - Indexing status changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Indexing status changed");
    }
    if(reason & USN_REASON_HARD_LINK_CHANGE){
        wprintf(L"  - Hard link changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Hard link changed");
    }
    if(reason & USN_REASON_COMPRESSION_CHANGE){
        wprintf(L"  - Compression changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Compression changed");
    }
    if(reason & USN_REASON_ENCRYPTION_CHANGE){
        wprintf(L"  - Encryption changed\n");if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Encryption changed");
    }
    if(reason & USN_REASON_OBJECT_ID_CHANGE){
        wprintf(L"  - Object ID changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Object ID changed");
    }
    if(reason & USN_REASON_REPARSE_POINT_CHANGE){
        wprintf(L"  - Reparse point changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Reparse point changed");
    }
    if(reason & USN_REASON_STREAM_CHANGE){
        wprintf(L"  - Stream changed\n");
        if(!FirstReason)
            wcscat(EventReasons, L" | ");
        FirstReason = 0;
        wcscat(EventReasons, L"Stream changed");
    }

    wcscat(EventReasons, L"\n");

    //WriteFile(CSVHandle, EventReasons, (DWORD)sizeof(EventReasons), &bytesWritten, NULL);
    WriteWideStringAsUTF8(EventReasons);
    FlushFileBuffers(OutputCSV);
}

// Function to print file event message with full path and details
void PrintFileEventMessage(LPCWSTR fullPath, DWORD reason, USN Usn, LPSYSTEMTIME FileSystemTime, HANDLE *hEventSource){

    wchar_t FileNameAndID[1024] = {0};
    wchar_t EventString[1024] = {0};
    wchar_t EventReasons[1024] = {0};

    SYSTEMTIME LocalTime;
    SystemTimeToTzSpecificLocalTime(NULL, FileSystemTime, &LocalTime);

    printf("\n%02u/%02u/%u %02u:%02u:%02u\n", LocalTime.wMonth, LocalTime.wDay, LocalTime.wYear, LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond);

    wprintf(L"File: %s\n", fullPath);

    printf("%lld- \n", Usn);

    swprintf(FileNameAndID, sizeof(FileNameAndID) / sizeof(FileNameAndID[0]), L"%lld, %02u/%02u/%u, %02u:%02u:%02u, %s, ", Usn, LocalTime.wMonth, LocalTime.wDay, LocalTime.wYear, LocalTime.wHour, LocalTime.wMinute, LocalTime.wSecond, fullPath);

    PrintEventReason(reason, EventReasons);

    swprintf(EventString, sizeof(EventString) / sizeof(EventString[0]), L"%s, %s", fullPath, EventReasons);

    WriteWideStringAsUTF8(FileNameAndID);

    // Create a pointer array to hold the event message
    LPCWSTR EventStringArray[1];
    EventStringArray[0] = EventString;  // Assign the event message

    ReportEventW(*hEventSource,     // Event log handle
        EVENTLOG_INFORMATION_TYPE, // Event type
        0,                         // Event category
        (DWORD)Usn,                // Event identifier
        NULL,                      // No user SID
        1,                         // Number of strings
        0,                         // No binary data
        (LPCWSTR*)EventStringArray,              // Pointer to message
        NULL);
}

int IsRunningAsAdmin(){

    BOOL isAdmin = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)){
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)){
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    return isAdmin;
}

int RestartAsAdmin(int argc, wchar_t* argv[]){

    // Build the argument list to pass to the elevated instance
    wchar_t commandLine[1024] = {0};

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

void PrepareClose(int Signal){

    printf("NOOOOO DONT CLOSE ME");
    CloseHandle(OutputCSV);

    exit(Signal);
}

BOOL WINAPI ConsoleHandler(DWORD Signal) {
    if (Signal == CTRL_CLOSE_EVENT) {
        PrepareClose(CTRL_CLOSE_EVENT);
    }
    return TRUE;
}

#define MAX_LINES 1024   // Maximum number of lines to store
#define MAX_LINE_LENGTH 1024  // Maximum length of a single line

// Function to read a UTF-8 file and convert its contents to UTF-16 (wide strings)
int ReadFileToArray(LPCWSTR filename, LPCWSTR **lines, int *lineCount){
    // Open the file for reading
    HANDLE hFile = CreateFileW(filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        wprintf(L"Failed to open file: %s\n", filename);
        return -1;
    }

    // Get the file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if(fileSize == INVALID_FILE_SIZE){
        wprintf(L"Failed to get file size\n");
        CloseHandle(hFile);
        return -1;
    }

    // Allocate memory for the UTF-8 content
    char *utf8Content = (char *)malloc(fileSize + 1); // +1 for null terminator
    if(!utf8Content){
        wprintf(L"Memory allocation error\n");
        CloseHandle(hFile);
        return -1;
    }

    // Read the UTF-8 content from the file
    DWORD bytesRead;
    if(!ReadFile(hFile, utf8Content, fileSize, &bytesRead, NULL)){
        wprintf(L"Failed to read file\n");
        free(utf8Content);
        CloseHandle(hFile);
        return -1;
    }
    utf8Content[fileSize] = '\0';  // Null-terminate the UTF-8 content

    CloseHandle(hFile);

    // Calculate the size required for the UTF-16 buffer
    int utf16Length = MultiByteToWideChar(CP_UTF8, 0, utf8Content, -1, NULL, 0);
    if(utf16Length == 0){
        wprintf(L"Failed to calculate UTF-16 buffer size\n");
        free(utf8Content);
        return -1;
    }

    // Allocate memory for the UTF-16 content
    WCHAR *utf16Content = (WCHAR *)malloc(utf16Length * sizeof(WCHAR));
    if(!utf16Content){
        wprintf(L"Memory allocation error for UTF-16 content\n");
        free(utf8Content);
        return -1;
    }

    // Convert the UTF-8 content to UTF-16 (wide characters)
    if(MultiByteToWideChar(CP_UTF8, 0, utf8Content, -1, utf16Content, utf16Length) == 0){
        wprintf(L"Failed to convert UTF-8 to UTF-16\n");
        free(utf8Content);
        free(utf16Content);
        return -1;
    }

    free(utf8Content);  // We no longer need the UTF-8 content

    // Allocate memory for storing lines
    *lines = (LPCWSTR *)malloc(MAX_LINES * sizeof(LPCWSTR));
    if(!*lines){
        wprintf(L"Memory allocation error for lines\n");
        free(utf16Content);
        return -1;
    }

    // Tokenize the UTF-16 content into lines
    WCHAR *line = wcstok(utf16Content, L"\r\n", NULL);
    int currentLineIndex = 0;
    *lineCount = 0;

    while(line != NULL && currentLineIndex < MAX_LINES){
        // Allocate memory for the current line and store it
        (*lines)[currentLineIndex] = _wcsdup(line);
        if(!(*lines)[currentLineIndex]){
            wprintf(L"Memory allocation error for line\n");
            free(utf16Content);
            return -1;
        }

        currentLineIndex++;
        (*lineCount)++;

        // Move to the next line
        line = wcstok(NULL, L"\r\n", NULL);
    }

    free(utf16Content);  // We no longer need the UTF-16 content
    return 0;
}

int wmain(int argc, wchar_t* argv[]){

    if(argc != 1)
        if(!wcscmp(argv[1], L"--help") || !wcscmp(argv[1], L"-h"))
            printf("USNTracker.exe [Options]\n\n-f (folderPath) | Only include events from this folder and its subfolders\n\n-b | Enable folder blacklist\n\n-w | Enable folder whitelist");

    // Make sure program is run as admin
    // and prompt to run as admin if not
    if(!IsRunningAsAdmin())
        return RestartAsAdmin(argc, argv);

    BOOL CustomFolder = 0;
    BOOL BlacklistEnabled = 0;
    BOOL WhitelistEnabled = 0;

    LPCWSTR *Blacklists;
    int NumOfBlacklists = 0;

    LPCWSTR *Whitelists;
    int NumOfWhitelists = 0;

    LPCWSTR targetFolder = L"C:\\";

    for(int i = 1; i < argc; i++){
        if(!wcscmp(argv[i], L"-f")){
            CustomFolder = 1;
            targetFolder = argv[i + 1];
        }
        else if(!wcscmp(argv[i], L"-b")){
            BlacklistEnabled = 1;
            ReadFileToArray(L".\\Lists\\Blacklist.txt", &Blacklists, &NumOfBlacklists);
        }
        else if(!wcscmp(argv[i], L"-w")){
            WhitelistEnabled = 1;
            ReadFileToArray(L".\\Lists\\Whitelist.txt", &Whitelists, &NumOfWhitelists);
        }
    }

    WhitelistEnabled = 1;
    ReadFileToArray(L".\\Lists\\Whitelist.txt", &Whitelists, &NumOfWhitelists);

    const LPCWSTR CSVFileName = L"USNLogs.csv";

    // Check if CSV file already exists
    DWORD CSVFileAttributes = GetFileAttributes(CSVFileName);
    int CSVAlreadyExists = (CSVFileAttributes != INVALID_FILE_ATTRIBUTES && !(CSVFileAttributes & FILE_ATTRIBUTE_DIRECTORY));

    //printf(CSVAlreadyExists ? "CSV Already Exists" : "CSV Doesn't Exist");

    OutputCSV = CreateFile(
        CSVFileName,               // File name
        FILE_APPEND_DATA,            // Append data
        FILE_SHARE_READ | FILE_SHARE_WRITE,  // Allow other processes to read/write
        NULL,                        // Default security
        OPEN_ALWAYS,                 // Open existing or create new file
        FILE_ATTRIBUTE_NORMAL,       // Normal file
        NULL                         // No template file
    );

    if (OutputCSV == INVALID_HANDLE_VALUE) {
        MessageBox(NULL, L"Failed to create/open USNLogs.csv", L"File Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Register the handler for console close event
    SetConsoleCtrlHandler(ConsoleHandler, TRUE);

    signal(SIGINT, PrepareClose);   // Ctrl+C
    signal(SIGTERM, PrepareClose);  // Termination signal
    signal(SIGABRT, PrepareClose);  // Abort signal
    //atexit(PrepareClose);            // Normal exit
    //at_quick_exit(PrepareClose);

    const char *data = "ID, Date, Time, FilePath, Changes\n";
    DWORD bytesWritten;

    if(!CSVAlreadyExists)
        WriteFile(OutputCSV, data, (DWORD)strlen(data), &bytesWritten, NULL);

    HANDLE hVol = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;
    BYTE buffer[BUFFER_SIZE] = { 0 };
    USN_JOURNAL_DATA usnJournalData;
    USN lastUsn = 0;

    // Open file pointer to the C drive
    hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if(hVol == INVALID_HANDLE_VALUE){
        printf("Failed to open C drive.\n");
        return 1;
    }

    // Get the USN Journal's properties
    if(!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, NULL, 0, &usnJournalData, sizeof(usnJournalData), &bytesReturned, NULL)){
        printf("Failed to query USN journal.\n");
        CloseHandle(hVol);
        return 1;
    }

    // Initialize Event Source
    HANDLE hEventSource = RegisterEventSourceW(NULL, L"USNTracker");

    if(hEventSource == NULL){
        printf("Failed to register the event source.\n");
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

    BOOL ValidEvent = 1;

    while(TRUE){

        readData.StartUsn = lastUsn;

        // Results in a max of ~800 logs a second
        // Also makes it use a lot less proccessing power
        Sleep(1);

        // Read USN journal
        if(DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData), buffer, BUFFER_SIZE, &bytesReturned, NULL)){
            USN_RECORD *usnRecord = (USN_RECORD *)&buffer[sizeof(USN)];
            while((BYTE *)usnRecord < buffer + bytesReturned){
                wchar_t fullPath[MAX_PATH];

                // Resolve the full path
                if(GetFullPathByFileReference(hVol, usnRecord->FileReferenceNumber, fullPath, MAX_PATH)){
                    // Check if the file is in the specified folder
                    if(IsFileInFolder(fullPath, targetFolder)){
                        // Print event message if the file is in the target folder

                        if(BlacklistEnabled){
                            for(int i = 0; i < NumOfBlacklists; i++)
                                if(IsInFolder(fullPath, Blacklists[i]))
                                    ValidEvent = 0;
                        }

                        if(WhitelistEnabled){
                            ValidEvent = 0;
                            for(int i = 0; i < NumOfWhitelists; i++)
                                if(IsInFolder(fullPath, Whitelists[i]))
                                    ValidEvent = 1;
                        }

                        if(ValidEvent){
                            FILETIME TempFileTime;

                            TempFileTime.dwHighDateTime = (DWORD)usnRecord->TimeStamp.HighPart;
                            TempFileTime.dwLowDateTime = usnRecord->TimeStamp.LowPart;

                            SYSTEMTIME FileSystemTime;

                            FileTimeToSystemTime(&TempFileTime, &FileSystemTime);

                            PrintFileEventMessage(fullPath, usnRecord->Reason, usnRecord->Usn, &FileSystemTime, &hEventSource);

                        }
                    }
                }

                // Reset for next event check
                ValidEvent = 1;

                // Update last processed USN
                lastUsn = usnRecord->Usn + usnRecord->RecordLength;

                // Move to the next USN record
                usnRecord = (USN_RECORD *)((PBYTE)usnRecord + usnRecord->RecordLength);
            }
        }
        else{
            printf("Failed to read USN journal.\n");
            break;
        }
    }

    // Clean up
    CloseHandle(hVol);
    return 0;
}
