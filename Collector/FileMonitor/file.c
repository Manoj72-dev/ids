#include <stdio.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>

#include "file.h"
#include "../Common/global.h"

void print_change_action(DWORD action, const WCHAR* fileName) {
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

void start_monitoring(DIR_MONITOR *monitor) {
    DWORD bytesReturned = 0;
    BOOL success = ReadDirectoryChangesW(
        monitor->dirHandle,
        monitor->buffer,
        BUFFER_SIZE,
        TRUE,
        FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
        FILE_NOTIFY_CHANGE_ATTRIBUTES | FILE_NOTIFY_CHANGE_SIZE |
        FILE_NOTIFY_CHANGE_LAST_WRITE,
        &bytesReturned,
        &monitor->overlapped,
        NULL
    );
    if (!success) {
        wprintf(L"Failed to start monitoring %ls. Error: %lu\n", monitor->directoryPath, GetLastError());
    }
}

unsigned __stdcall monitor_thread(void *arg) {
    DIR_MONITOR *monitor = (DIR_MONITOR *)arg;

    while (1) {
        start_monitoring(monitor);

        DWORD waitResult = WaitForSingleObject(monitor->overlapped.hEvent, INFINITE);

        if (waitResult == WAIT_OBJECT_0) {
            DWORD bytesTransferred = 0;

            if (GetOverlappedResult(monitor->dirHandle, &monitor->overlapped, &bytesTransferred, FALSE)) {
                char *ptr = (char *)monitor->buffer;
                FILE_NOTIFY_INFORMATION *fni;

                do {
                    fni = (FILE_NOTIFY_INFORMATION *)ptr;

                    WCHAR fileName[MAX_PATH];
                    wcsncpy_s(fileName, MAX_PATH, fni->FileName, fni->FileNameLength / sizeof(WCHAR));
                    fileName[fni->FileNameLength / sizeof(WCHAR)] = L'\0';

                    wprintf(L"[Thread %u] Path: %ls ", GetCurrentThreadId(), monitor->directoryPath);
                    print_change_action(fni->Action, fileName);

                    if (fni->NextEntryOffset == 0) break;
                    ptr += fni->NextEntryOffset;
                } while (TRUE);
            } else {
                wprintf(L"GetOverlappedResult failed. Error: %lu\n", GetLastError());
                break;
            }
        } else {
            wprintf(L"Wait error in thread %u. Error: %lu\n", GetCurrentThreadId(), GetLastError());
            break;
        }
    }

    CloseHandle(monitor->dirHandle);
    CloseHandle(monitor->overlapped.hEvent);
    free(monitor);

    _endthreadex(0);
    return 0;
}

DWORD WINAPI file_monitor_thread(LPVOID lpParam){
    wchar_t **directories = (wchar_t **)lpParam;
    
    for (int i = 0; directories[i] !=NULL; i++) {
        DIR_MONITOR *monitor = (DIR_MONITOR *)malloc(sizeof(DIR_MONITOR));
        ZeroMemory(monitor, sizeof(DIR_MONITOR));

        monitor->dirHandle = CreateFileW(
            directories[i],
            FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );

        if (monitor->dirHandle == INVALID_HANDLE_VALUE) {
            wprintf(L"Failed to open directory %ls. Error: %lu\n", directories[i], GetLastError());
            free(monitor);
            continue;
        }

        wcscpy_s(monitor->directoryPath, MAX_PATH, directories[i]);
        monitor->overlapped.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);

        uintptr_t threadHandle = _beginthreadex(NULL, 0, monitor_thread, monitor, 0, NULL);
        CloseHandle((HANDLE)threadHandle);
    }

    while (1) {
        Sleep(1000);
    }

    return 0;
}
