#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h>

typedef struct {
    HKEY rootKey;
    const wchar_t *subkey;
    HKEY handle;
    HANDLE event;
    struct {
        wchar_t name[256];
        DWORD type;
        BYTE data[1024];
        DWORD dataSize;
    }values[50];
    DWORD valueCount;
} REG_MONITOR;

const char* hkey_to_string(HKEY hKey);
const char* reg_type_to_string(DWORD type);
void start_reg_monitoring(REG_MONITOR *mon);
void snapshot(REG_MONITOR *reg);
DWORD WINAPI registry_monitor_thread(LPVOID param);

#endif //REGISTRY_H