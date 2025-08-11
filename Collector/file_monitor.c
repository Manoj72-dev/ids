#include<stdio.h>
#include<windows.h>
#include<winbase.h>
#include<stdlib.h>

#define BUFFER_SIZE 1024

void PrintChangeAction(DWORD action, const WCHAR* fileName) {
    switch (action) {
        case FILE_ACTION_ADDED:
            wprintf(L"Added: %ls\n", fileName);
            break;
        case FILE_ACTION_REMOVED:
            wprintf(L"Removed: %ls\n", fileName);
            break;
        case FILE_ACTION_MODIFIED:
            wprintf(L"Modified: %ls\n", fileName);
            break;
        case FILE_ACTION_RENAMED_OLD_NAME:
            wprintf(L"Renamed From: %ls\n", fileName);
            break;
        case FILE_ACTION_RENAMED_NEW_NAME:
            wprintf(L"Renamed To: %ls\n", fileName);
            break;
        default:
            wprintf(L"Unknown action: %d on %ls\n", action, fileName);
    }
}

typedef struct {
    HANDLE dirHandle;
    OVERLAPPED overlapped;
    BYTE buffer[BUFFER_SIZE];
    wchar_t directoryPath[MAX_PATH];
} DIR_MONITOR;


void StartMonitoring(DIR_MONITOR *monitor){
    DWORD bytesReturned = 0;
    BOOL success = ReadDirectoryChangesW(
        monitor->dirHandle,
        monitor->buffer,
        BUFFER_SIZE,
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_LAST_WRITE,
        &bytesReturned,
        &monitor->overlapped,
        NULL
    );
    if(!success){
        wprintf(L"Failed to start monitoring %s. Error: %lu\n", monitor->directoryPath, GetLastError());
    }
}

int main(){
    const wchar_t* directories[] = {
        L"C:\\Windows\\System32",
        L"C:\\Windows\\System32\\drivers ",
        L"C:\\Windows\\Temp",
        L"C:\\Users\\manoj\\Documents"
    };
    const int dirCount = sizeof(directories)/sizeof(directories[0]);
    DIR_MONITOR monitors[dirCount];
    HANDLE events[dirCount];

    for(int i=0 ;i<dirCount; i++){
        ZeroMemory(&monitors[i], sizeof(DIR_MONITOR));
        monitors[i].dirHandle = CreateFileW(
            directories[i],
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );

        if(monitors[i].dirHandle == INVALID_HANDLE_VALUE){
            wprintf(L"Failed to open directory %s. Error: %lu\n", directories[i], GetLastError());
            return 1;
        }

        wcscpy_s(monitors[i].directoryPath,MAX_PATH, directories[i]);

        monitors[i].overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE,NULL);
        events[i] = monitors[i].overlapped.hEvent;

        StartMonitoring(&monitors[i]);
    }
    while(TRUE){
        DWORD WaitStatus = WaitForMultipleObjects(dirCount, events, FALSE, INFINITE);

        if(WaitStatus >= WAIT_OBJECT_0 && WaitStatus < WAIT_OBJECT_0 + dirCount){
            int idx = WaitStatus - WAIT_OBJECT_0;
            DWORD bytesTransferred = 0;

            if(GetOverlappedResult(monitors[idx].dirHandle,&monitors[idx].overlapped,&bytesTransferred,FALSE)){
                char *ptr = (char *)monitors[idx].buffer;
                FILE_NOTIFY_INFORMATION *fni;

                do{
                    fni = (FILE_NOTIFY_INFORMATION *)ptr;
                    wprintf(L"Path: %ls ",monitors[idx].directoryPath);
                    PrintChangeAction(fni->Action, fni->FileName);
                    if(fni->NextEntryOffset ==0 )break;
                    ptr += fni->NextEntryOffset;
                } while(TRUE);

                StartMonitoring(&monitors[idx]);
            }
            else{
                wprintf(L"GetOverlappedResult failed. Error: %lu\n", GetLastError());
            }
        }
        else{
            wprintf(L"Wait error or timeout. Code: %lu\n", GetLastError());
            break;
        }
    }

    for (int i = 0; i < dirCount; i++) {
        CloseHandle(monitors[i].dirHandle);
        CloseHandle(monitors[i].overlapped.hEvent);
    }
    return 0;
}
