#ifndef FILE_H
#define FILE_H

#include <windows.h>
#include <stdio.h>

#define BUFFER_SIZE 1024

typedef struct {
    HANDLE dirHandle;
    WCHAR directoryPath[MAX_PATH];
    char buffer[BUFFER_SIZE];
    OVERLAPPED overlapped;
} DIR_MONITOR;

char* wchar_to_char(const WCHAR* wstr);
char *get_action(DWORD action);
void start_monitoring(DIR_MONITOR *monitor);
unsigned __stdcall monitor_thread(void *arg);
DWORD WINAPI file_monitor_thread(LPVOID lpParam);

#endif //FILE_H