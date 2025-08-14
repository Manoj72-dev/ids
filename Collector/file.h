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

void print_change_action(DWORD action, const WCHAR* fileName);
void start_monitoring(DIR_MONITOR *monitor);
unsigned __stdcall monitor_thread(void *arg);
DWORD WINAPI moniter(LPVOID lpParam);

#endif //FILE_H