#include<stdio.h>
#include<windows.h>
#include<winbase.h>
#include<stdlib.h>

#define BUFFER_SIZE 1024

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
        L"C:\\Windows\\System32"
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
}
