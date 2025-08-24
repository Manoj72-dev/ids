#ifndef REGISTRY_H
#define REGISTRY_H

#include <windows.h>

#define MAX_REG_VALUES 50

typedef struct {
    wchar_t name[256];
    DWORD type;
    BYTE data[1024];
    DWORD dataSize;
} REG_VALUE;

typedef struct {
    HKEY rootKey;
    wchar_t *subkey;
    HKEY handle;
    HANDLE event;
    REG_VALUE values[MAX_REG_VALUES];
    DWORD valueCount;
} REG_MONITOR;

typedef struct {
    REG_MONITOR *monitors;
    int count;
} REG_PARAM;

const char* hkey_to_string(HKEY hKey);
const char* reg_type_to_string(DWORD type);
void start_reg_monitoring(REG_MONITOR *mon);
void snapshot(REG_MONITOR *reg);
void send_registry_json(REG_MONITOR *regMon, REG_VALUE *val);
DWORD WINAPI registry_monitor_thread(LPVOID param);

#endif // REGISTRY_H
