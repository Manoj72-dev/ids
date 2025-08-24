#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>
#include <time.h>

#include "state.h"
#include "../Common/global.h"
#include "../Third_party/cjson.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


static const char *GetStateStr(DWORD s) {
    switch ((int)s) {
        case 1:  return "CLOSED";
        case 2:  return "LISTEN";
        case 3:  return "SYN-SENT";
        case 4:  return "SYN-RECEIVED";
        case 5:  return "ESTABLISHED";
        case 6:  return "FIN-WAIT-1";
        case 7:  return "FIN-WAIT-2";
        case 8:  return "CLOSE-WAIT";
        case 9:  return "CLOSING";
        case 10: return "LAST-ACK";
        case 11: return "TIME-WAIT";
        case 12: return "DELETE TCB";
        default: return "UNKNOWN";
    }
}

static char *GetProcessNameBase(DWORD pid) {
    if (pid == 4) return _strdup("System");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return _strdup("Unknown");

    char fullPath[MAX_PATH];
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageNameA(hProcess, 0, fullPath, &size)) {
        CloseHandle(hProcess);
        return _strdup("Unknown");
    }
    CloseHandle(hProcess);

    char *baseName = strrchr(fullPath, '\\');
    if (baseName) baseName++;
    else baseName = fullPath;

    return _strdup(baseName);
}

static void send_tcp_json_v4(const char *localIP, USHORT lport,
                             const char *remoteIP, USHORT rport,
                             DWORD pid, const char *procName, DWORD state)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "Type", "State");
    cJSON_AddStringToObject(obj, "Protocol", "TCP");
    cJSON_AddStringToObject(obj, "Version", "IPv4");
    cJSON_AddStringToObject(obj, "LocalIP", localIP);
    cJSON_AddNumberToObject(obj, "LocalPort", (int)lport);
    cJSON_AddStringToObject(obj, "RemoteIP", remoteIP);
    cJSON_AddNumberToObject(obj, "RemotePort", (int)rport);
    cJSON_AddStringToObject(obj, "State", GetStateStr(state));
    cJSON_AddNumberToObject(obj, "PID", (double)pid);
    cJSON_AddStringToObject(obj, "Process", procName ? procName : "Unknown");
    cJSON_AddNumberToObject(obj, "ts", (double)time(NULL));
    send_json(hPipeMon, obj);
}

static void send_tcp_json_v6(const char *localIP, USHORT lport,
                             const char *remoteIP, USHORT rport,
                             DWORD pid, const char *procName, DWORD state)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "Type", "State");
    cJSON_AddStringToObject(obj, "Protocol", "TCP");
    cJSON_AddStringToObject(obj, "Version", "IPv6");
    cJSON_AddStringToObject(obj, "LocalIP", localIP);
    cJSON_AddNumberToObject(obj, "LocalPort", (int)lport);
    cJSON_AddStringToObject(obj, "RemoteIP", remoteIP);
    cJSON_AddNumberToObject(obj, "RemotePort", (int)rport);
    cJSON_AddStringToObject(obj, "State", GetStateStr(state));
    cJSON_AddNumberToObject(obj, "PID", (double)pid);
    cJSON_AddStringToObject(obj, "Process", procName ? procName : "Unknown");
    cJSON_AddNumberToObject(obj, "ts", (double)time(NULL));
    send_json(hPipeMon, obj);
}

static void send_udp_json_v4(const char *localIP, USHORT lport,
                             DWORD pid, const char *procName)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "Type", "State");
    cJSON_AddStringToObject(obj, "Protocol", "UDP");
    cJSON_AddStringToObject(obj, "Version", "IPv4");
    cJSON_AddStringToObject(obj, "LocalIP", localIP);
    cJSON_AddNumberToObject(obj, "LocalPort", (int)lport);
    cJSON_AddNumberToObject(obj, "PID", (double)pid);
    cJSON_AddStringToObject(obj, "Process", procName ? procName : "Unknown");
    cJSON_AddNumberToObject(obj, "ts", (double)time(NULL));
    send_json(hPipeMon, obj);
}

static void send_udp_json_v6(const char *localIP, USHORT lport, DWORD scopeId,
                             DWORD pid, const char *procName)
{
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "Type", "State");
    cJSON_AddStringToObject(obj, "Protocol", "UDP");
    cJSON_AddStringToObject(obj, "Version", "IPv6");
    cJSON_AddStringToObject(obj, "LocalIP", localIP);
    cJSON_AddNumberToObject(obj, "LocalPort", (int)lport);
    cJSON_AddNumberToObject(obj, "ScopeId", (double)scopeId);
    cJSON_AddNumberToObject(obj, "PID", (double)pid);
    cJSON_AddStringToObject(obj, "Process", procName ? procName : "Unknown");
    cJSON_AddNumberToObject(obj, "ts", (double)time(NULL));
    send_json(hPipeMon, obj);
}

static void TCP_snapshot(void) {
    PMIB_TCPTABLE_OWNER_PID  t4 = NULL;
    PMIB_TCP6TABLE_OWNER_PID t6 = NULL;
    DWORD sz4 = 0, sz6 = 0;

    if (GetExtendedTcpTable(NULL, &sz4, TRUE, AF_INET,  TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        send_error(hPipeErr, "GetExtendedTcpTable preflight v4 failed", GetLastError());
        return;
    }
    if (GetExtendedTcpTable(NULL, &sz6, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) {
        send_error(hPipeErr, "GetExtendedTcpTable preflight v6 failed", GetLastError());
        return;
    }

    t4 = (PMIB_TCPTABLE_OWNER_PID)malloc(sz4);
    t6 = (PMIB_TCP6TABLE_OWNER_PID)malloc(sz6);
    if (!t4 || !t6) {
        send_error(hPipeErr, "TCP table alloc failed", ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    if (GetExtendedTcpTable(t4, &sz4, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t4->dwNumEntries; i++) {
            struct in_addr la = { t4->table[i].dwLocalAddr };
            struct in_addr ra = { t4->table[i].dwRemoteAddr };
            char *proc = GetProcessNameBase(t4->table[i].dwOwningPid);

            send_tcp_json_v4(
                inet_ntoa(la),
                ntohs((u_short)t4->table[i].dwLocalPort),
                inet_ntoa(ra),
                ntohs((u_short)t4->table[i].dwRemotePort),
                t4->table[i].dwOwningPid,
                proc,
                t4->table[i].dwState
            );

            free(proc);
        }
    } else {
        send_error(hPipeErr, "GetExtendedTcpTable v4 failed", GetLastError());
    }

    if (GetExtendedTcpTable(t6, &sz6, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < t6->dwNumEntries; i++) {
            char localbuf[INET6_ADDRSTRLEN], remotebuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(t6->table[i].ucLocalAddr),  localbuf,  sizeof(localbuf));
            inet_ntop(AF_INET6, &(t6->table[i].ucRemoteAddr), remotebuf, sizeof(remotebuf));

            char *proc = GetProcessNameBase(t6->table[i].dwOwningPid);

            send_tcp_json_v6(
                localbuf,
                ntohs((u_short)t6->table[i].dwLocalPort),
                remotebuf,
                ntohs((u_short)t6->table[i].dwRemotePort),
                t6->table[i].dwOwningPid,
                proc,
                t6->table[i].dwState
            );

            free(proc);
        }
    } else {
        send_error(hPipeErr, "GetExtendedTcpTable v6 failed", GetLastError());
    }

cleanup:
    if (t4) free(t4);
    if (t6) free(t6);
}

static void UDP_snapshot(void) {
    PMIB_UDPTABLE_OWNER_PID  u4 = NULL;
    PMIB_UDP6TABLE_OWNER_PID u6 = NULL;
    DWORD sz4 = 0, sz6 = 0;

    if (GetExtendedUdpTable(NULL, &sz4, TRUE, AF_INET,  UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
        send_error(hPipeErr, "GetExtendedUdpTable preflight v4 failed", GetLastError());
        return;
    }
    if (GetExtendedUdpTable(NULL, &sz6, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) {
        send_error(hPipeErr, "GetExtendedUdpTable preflight v6 failed", GetLastError());
        return;
    }

    u4 = (PMIB_UDPTABLE_OWNER_PID)malloc(sz4);
    u6 = (PMIB_UDP6TABLE_OWNER_PID)malloc(sz6);
    if (!u4 || !u6) {
        send_error(hPipeErr, "UDP table alloc failed", ERROR_NOT_ENOUGH_MEMORY);
        goto cleanup;
    }

    if (GetExtendedUdpTable(u4, &sz4, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < u4->dwNumEntries; i++) {
            struct in_addr la = { u4->table[i].dwLocalAddr };
            char *proc = GetProcessNameBase(u4->table[i].dwOwningPid);

            send_udp_json_v4(
                inet_ntoa(la),
                ntohs((u_short)u4->table[i].dwLocalPort),
                u4->table[i].dwOwningPid,
                proc
            );

            free(proc);
        }
    } else {
        send_error(hPipeErr, "GetExtendedUdpTable v4 failed", GetLastError());
    }

    if (GetExtendedUdpTable(u6, &sz6, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < u6->dwNumEntries; i++) {
            char localbuf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(u6->table[i].ucLocalAddr), localbuf, sizeof(localbuf));
            char *proc = GetProcessNameBase(u6->table[i].dwOwningPid);

            send_udp_json_v6(
                localbuf,
                ntohs((u_short)u6->table[i].dwLocalPort),
                u6->table[i].dwLocalScopeId,
                u6->table[i].dwOwningPid,
                proc
            );

            free(proc);
        }
    } else {
        send_error(hPipeErr, "GetExtendedUdpTable v6 failed", GetLastError());
    }

cleanup:
    if (u4) free(u4);
    if (u6) free(u6);
}


DWORD WINAPI TCP_table_thread(LPVOID Param) {
    (void)Param;
    for (;;) {
        TCP_snapshot();
        Sleep(5000);
    }
    return 0;
}

DWORD WINAPI UDP_table_thread(LPVOID Param) {
    (void)Param;
    for (;;) {
        UDP_snapshot();
        Sleep(2000); 
    }
    return 0;
}
