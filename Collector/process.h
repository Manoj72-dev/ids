#ifndef PROCESS_H
#define PROCESS_H

#include<windows.h>

#define PROCESS_NAME_SYSTEM  "System"
#define PROCESS_NAME_UNKNOWN "Unknown"
#define PROCESS_ACCESS_DENIED "Access Denied"

int GetProcessUser(DWORD pid, char *userName, DWORD userNameSize);
char *GetProcessPath(DWORD pid);
void EnumerateProcesses();
DWORD WINAPI Process_monitor_thread(LPVOID Param);

#endif // PROCESS_H