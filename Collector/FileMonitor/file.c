#include <stdio.h>
#include <windows.h>
#include <process.h>
#include <stdlib.h>

#include "file.h"
#include "../Common/global.h"
#include "../Third_party/cjson.h"

char* wchar_to_char(const WCHAR* wstr) {
    if (!wstr) return NULL;

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char *str = (char*)malloc(size_needed);
    if (!str) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, size_needed, NULL, NULL);
    return str;
}
char *get_action(DWORD action) {
    switch (action) {
        case FILE_ACTION_ADDED:
            return "Added";
        case FILE_ACTION_REMOVED:
            return "Removed";
        case FILE_ACTION_MODIFIED:
           return "Modefied";
        case FILE_ACTION_RENAMED_OLD_NAME:
            return "Renamed From";
        case FILE_ACTION_RENAMED_NEW_NAME:
            return "Renamed To";
        default:
            return "Unknown Action";
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
        char err[514];
        char dir_name[256];
        wcstombs(dir_name, monitor->directoryPath, sizeof(dir_name));
        dir_name[sizeof(dir_name)-1] = '\0';
        snprintf(err,sizeof(err),"Failed to start monitoring %s.", monitor->directoryPath);
        send_error(hPipeErr, err, GetLastError());
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
                    char *path = wchar_to_char(monitor->directoryPath);
                    char *filename = wchar_to_char(fni->FileName);
                    cJSON *msg = cJSON_CreateObject();
                    cJSON_AddStringToObject(msg,"Type", "File");
                    cJSON_AddStringToObject(msg,"Path", path);
                    cJSON_AddStringToObject(msg,"FileName",filename);
                    cJSON_AddStringToObject(msg,"Action",get_action(fni->Action));
                    send_json(hPipeMon, msg);
                    if (fni->NextEntryOffset == 0) break;
                    ptr += fni->NextEntryOffset;
                } while (TRUE);
            } else {
                send_error(hPipeErr,"GetOverlappedResult failed.", GetLastError());
                break;
            }
        } else {
            char err[214];
            snprintf(err,sizeof(err),"Wait error in thread %u.", GetCurrentThreadId());
            send_error(hPipeErr, err, GetLastError());
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
            char err[514];
            char dir_name[256];
            wcstombs(dir_name, directories[i], sizeof(dir_name));
            dir_name[sizeof(dir_name)-1] = '\0';

            snprintf(err, sizeof(err), "Failed to open directory %s.", dir_name);

            send_error(hPipeErr, err, GetLastError());
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
