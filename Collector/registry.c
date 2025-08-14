#include <windows.h>
#include <stdio.h>

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

void StartRegMonitoring(REG_MONITOR *mon) {
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

void SnapShort(REG_MONITOR *reg) {
    DWORD index = 0;
    reg->valueCount = 0;

    while (1) {
        DWORD nameSize = 256;
        DWORD dataSize = sizeof(reg->values[index].data);
        DWORD type;

        LONG res = RegEnumValueW(
            reg->handle,  // FIXED: use opened handle, not rootKey
            index,
            reg->values[index].name,
            &nameSize,
            NULL,
            &type,
            reg->values[index].data, // FIXED: index-specific
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
    reg->valueCount = index; // FIXED: moved outside loop
}

void compare(REG_MONITOR *reg){
    REG_MONITOR temp = *reg;
    SnapShort(&temp);
    for(DWORD i=0;i<temp.valueCount;i++){
        int found =0;
        for(DWORD j=0; j< reg->valueCount ;j++ ){
            if(wcscmp(temp.values[i].name, reg->values[j].name) == 0){
                found = 1;
                if(temp.values[i].dataSize != reg->values[j].dataSize ||  
                    memcmp(temp.values[i].data, reg->values[j].data, temp.values[i].dataSize) != 0){
                        wprintf(L"[ALERT] Key %ls: Value changed: %ls\n",reg->subkey, temp.values[i].name);
                    }
                break;
            }
        }
        if (!found) {
            wprintf(L"[ALERT] Key %ls: New value added: %ls\n", reg->subkey, temp.values[i].name);
        }
    }

    for (DWORD j = 0; j < reg->valueCount; j++) {
        int found = 0;
        for (DWORD i = 0; i < temp.valueCount; i++) {
            if (wcscmp(temp.values[i].name, reg->values[j].name) == 0) {
                found = 1; break;
            }
        }
        if (!found) {
            wprintf(L"[ALERT] Key %ls: Value deleted: %ls\n", reg->subkey, reg->values[j].name);
        }
    }
    *reg = temp;
}

int main() {
    REG_MONITOR monitors[] = {
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" },
        { HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" },
        { HKEY_CURRENT_USER, L"Software\\TestKey" },
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

        monitors[i].event = CreateEvent(NULL, FALSE, FALSE, NULL); // FIXED: create event first
        if (!monitors[i].event) {
            wprintf(L"[!] Failed to create event for %ls\n", monitors[i].subkey);
            continue;
        }

        SnapShort(&monitors[i]);         // Take initial snapshot
        StartRegMonitoring(&monitors[i]); // Set notification AFTER event created
    }

    while (1) {
        HANDLE eventList[regCount];
        for (int i = 0; i < regCount; i++) {
            eventList[i] = monitors[i].event;
        }
        DWORD waitResult = WaitForMultipleObjects(regCount, eventList, FALSE, INFINITE);
        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + regCount) {
            int index = waitResult - WAIT_OBJECT_0;
            compare(&monitors[index]); // FIXED: compare snapshot differences
            StartRegMonitoring(&monitors[index]); // Re-arm notification
        }
    }
}