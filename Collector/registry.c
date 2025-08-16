#include <windows.h>
#include <stdio.h>

#include "registry.h"

const char* hkey_to_string(HKEY hKey) {
    if (hKey == HKEY_CLASSES_ROOT)   return "HKEY_CLASSES_ROOT";
    if (hKey == HKEY_CURRENT_USER)   return "HKEY_CURRENT_USER";
    if (hKey == HKEY_LOCAL_MACHINE)  return "HKEY_LOCAL_MACHINE";
    if (hKey == HKEY_USERS)          return "HKEY_USERS";
    if (hKey == HKEY_CURRENT_CONFIG) return "HKEY_CURRENT_CONFIG";
    return "UNKNOWN_HKEY";
}

const char* reg_type_to_string(DWORD type) {
    switch (type) {
        case REG_SZ: return "REG_SZ";
        case REG_EXPAND_SZ: return "REG_EXPAND_SZ";
        case REG_MULTI_SZ: return "REG_MULTI_SZ";
        case REG_DWORD: return "REG_DWORD";
        case REG_QWORD: return "REG_QWORD";
        case REG_BINARY: return "REG_BINARY";
        default: return "UNKNOWN";
    }
}

void log_data(const REG_MONITOR *regMon) {
    wprintf(L"[KEY]   %hs\\%ls\n",hkey_to_string(regMon->rootKey), regMon->subkey);

    for (DWORD i = 0; i < regMon->valueCount; i++) {
        wprintf(L"  [VALUE] Name: %ls\t Type: %hs\t Size: %lu\n",
                regMon->values[i].name[0] ? regMon->values[i].name : L"(Default)",
                reg_type_to_string(regMon->values[i].type),
                regMon->values[i].dataSize);

        switch (regMon->values[i].type) {
            case REG_SZ:
            case REG_EXPAND_SZ:
                wprintf(L"          Data: %ls\n", (wchar_t*)regMon->values[i].data);
                break;

            case REG_DWORD:
                if (regMon->values[i].dataSize >= sizeof(DWORD)) {
                    DWORD val = *(DWORD*)regMon->values[i].data;
                    wprintf(L"          Data: 0x%08X (%u)\n", val, val);
                }
                break;

            case REG_QWORD:
                if (regMon->values[i].dataSize >= sizeof(ULONGLONG)) {
                    ULONGLONG val = *(ULONGLONG*)regMon->values[i].data;
                    wprintf(L"          Data: 0x%016llX (%llu)\n", val, val);
                }
                break;

            case REG_BINARY:
            default:
                wprintf(L"          Data (hex): ");
                for (DWORD j = 0; j < regMon->values[i].dataSize; j++) {
                    wprintf(L"%02X ", regMon->values[i].data[j]);
                    if ((j + 1) % 16 == 0) wprintf(L"\n                     ");
                }
                wprintf(L"\n");
                break;
        }
    }
}

void start_reg_monitoring(REG_MONITOR *mon) {
    if (RegNotifyChangeKeyValue(
        mon->handle,
        TRUE,
        REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
        mon->event,
        TRUE) != ERROR_SUCCESS)
    {
        wprintf(L"[!] Failed to set registry notification for %ls\n", mon->subkey);
    }
    
}

void snapshot(REG_MONITOR *reg) {
    DWORD index = 0;
    reg->valueCount = 0;

    while (index < 50) {
        DWORD nameSize = 256;
        DWORD dataSize = sizeof(reg->values[index].data);
        DWORD type;

        LONG res = RegEnumValueW(
            reg->handle,  
            index,
            reg->values[index].name,
            &nameSize,
            NULL,
            &type,
            reg->values[index].data, 
            &dataSize
        );

        if (res == ERROR_NO_MORE_ITEMS) break;
        if (res == ERROR_SUCCESS) {
            reg->values[index].type = type;
            reg->values[index].dataSize = dataSize;
            index++;
        } else {
            break;
        }
    }
    reg->valueCount = index;
    log_data(reg);
}

DWORD WINAPI registry_monitor_thread(LPVOID param) {
    REG_MONITOR monitors[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Shell Extensions" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces" },
        { HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows Defender" },
        { HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" }
    };
    const int regCount = sizeof(monitors) / sizeof(monitors[0]);

    HANDLE eventList[regCount];
    for (int i = 0; i < regCount; i++) {
        LONG res = RegOpenKeyExW(
            monitors[i].rootKey,
            monitors[i].subkey,
            0,
            KEY_READ | KEY_NOTIFY,
            &monitors[i].handle
        );
        if (res != ERROR_SUCCESS) {
            wprintf(L"[!] Failed to open key: %ls (Error: %ld)\n", monitors[i].subkey, res);
            monitors[i].event = NULL;
            continue;
        }

        monitors[i].event = CreateEvent(NULL, FALSE, FALSE, NULL); 
        eventList[i] = monitors[i].event;
        if (!monitors[i].event) {
            wprintf(L"[!] Failed to create event for %ls\n", monitors[i].subkey);
            continue;
        }

        snapshot(&monitors[i]);        
        start_reg_monitoring(&monitors[i]); 
    }

    while (1) {
        DWORD waitResult = WaitForMultipleObjects(regCount, eventList, FALSE, INFINITE);
        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + regCount) {
            int index = waitResult - WAIT_OBJECT_0;
            snapshot(&monitors[index]);
            start_reg_monitoring(&monitors[index]); 
        }
    }

    for (int i = 0; i < regCount; i++) {
        if (monitors[i].handle) RegCloseKey(monitors[i].handle);
        if (monitors[i].event) CloseHandle(monitors[i].event);
    }
}