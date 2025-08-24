#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "registry.h"
#include "../Common/global.h"
#include "../Third_party/cjson.h"

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

static void WideToUtf8(const wchar_t *src, char *dst, size_t dstSize) {
    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dstSize, NULL, NULL);
}

void send_registry_json(REG_MONITOR *regMon, REG_VALUE *val) {
    char subKeyUtf8[512], valueNameUtf8[256], dataStr[512];

    WideToUtf8(regMon->subkey, subKeyUtf8, sizeof(subKeyUtf8));
    WideToUtf8(val->name[0] ? val->name : L"(Default)", valueNameUtf8, sizeof(valueNameUtf8));

    switch (val->type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            WideToUtf8((wchar_t *)val->data, dataStr, sizeof(dataStr));
            break;
        case REG_DWORD:
            snprintf(dataStr, sizeof(dataStr), "%u", *(DWORD *)val->data);
            break;
        case REG_QWORD:
            snprintf(dataStr, sizeof(dataStr), "%llu", *(unsigned long long *)val->data);
            break;
        default:
            snprintf(dataStr, sizeof(dataStr), "BINARY[%lu bytes]", val->dataSize);
            break;
    }

    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "Type", "Registry");
    cJSON_AddStringToObject(obj, "RootKey", hkey_to_string(regMon->rootKey));
    cJSON_AddStringToObject(obj, "SubKey", subKeyUtf8);
    cJSON_AddStringToObject(obj, "ValueName", valueNameUtf8);
    cJSON_AddStringToObject(obj, "DataType", reg_type_to_string(val->type));
    cJSON_AddStringToObject(obj, "Data", dataStr);
    cJSON_AddNumberToObject(obj, "ts", (double)time(NULL));

    send_json(hPipeMon, obj);
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
            send_registry_json(reg, &reg->values[index]);
            index++;
        } else {
            send_error(hPipeErr, "RegEnumValue failed", res);
            break;
        }
    }
    reg->valueCount = index;
}

DWORD WINAPI registry_monitor_thread(LPVOID param) {
    REG_PARAM *p = (REG_PARAM *)param;
    REG_MONITOR *monitors = p->monitors;
    int regCount = p->count;

    HANDLE *eventList = malloc(sizeof(HANDLE) * regCount);
    if (!eventList) {
        send_error(hPipeErr, "Failed to allocate eventList", ERROR_NOT_ENOUGH_MEMORY);
        return 1;
    }

    for (int i = 0; i < regCount; i++) {
        LONG res = RegOpenKeyExW(monitors[i].rootKey, monitors[i].subkey, 0, KEY_READ | KEY_NOTIFY, &monitors[i].handle);
        if (res != ERROR_SUCCESS) {
            send_error(hPipeErr, "Failed to open registry key", res);
            monitors[i].event = NULL;
            continue;
        }

        monitors[i].event = CreateEvent(NULL, FALSE, FALSE, NULL);
        eventList[i] = monitors[i].event;
        if (!monitors[i].event) {
            send_error(hPipeErr, "Failed to create event", GetLastError());
            continue;
        }

        snapshot(&monitors[i]);

        if (RegNotifyChangeKeyValue(monitors[i].handle, TRUE,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
            monitors[i].event, TRUE) != ERROR_SUCCESS) {
            send_error(hPipeErr, "Failed to set registry notification", GetLastError());
        }
    }

    while (1) {
        DWORD waitResult = WaitForMultipleObjects(regCount, eventList, FALSE, INFINITE);
        if (waitResult >= WAIT_OBJECT_0 && waitResult < WAIT_OBJECT_0 + regCount) {
            int index = waitResult - WAIT_OBJECT_0;
            snapshot(&monitors[index]);
            RegNotifyChangeKeyValue(monitors[index].handle, TRUE,
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                monitors[index].event, TRUE);
        }
    }

    free(eventList);
    return 0;
}
