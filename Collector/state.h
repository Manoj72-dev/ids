#ifndef STATE_H
#define STATE_H

#include <windows.h>

char *GetState(DWORD par);
char *GetProcessName(DWORD pid);
void TCP_snapshot();
void UDP_snapshot();
DWORD WINAPI TCP_table_thread(LPVOID Param);
DWORD WINAPI UDP_table_thread(LPVOID Param);

#endif  // STATE_H