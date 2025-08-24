#ifndef STATE_H
#define STATE_H

#include <windows.h>

DWORD WINAPI TCP_table_thread(LPVOID Param);

DWORD WINAPI UDP_table_thread(LPVOID Param);

#endif // STATE_H
