#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <psapi.h>
#include <tchar.h>

#include "state.h"

char *GetState(DWORD par) {
    switch ((int)par) {
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

char *GetProcessName(DWORD pid) {
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


void TCP_snapshot() {
    PMIB_TCPTABLE_OWNER_PID tcpTable = NULL;
    PMIB_TCP6TABLE_OWNER_PID v6tcpTable = NULL;
    DWORD tcpsize = 0, v6tcpsize = 0;

    if (GetExtendedTcpTable(NULL, &tcpsize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    if (GetExtendedTcpTable(NULL, &v6tcpsize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) != ERROR_INSUFFICIENT_BUFFER) return;

    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(tcpsize);
    v6tcpTable = (PMIB_TCP6TABLE_OWNER_PID)malloc(v6tcpsize);

    if (!tcpTable || !v6tcpTable) goto cleanup;

    if (GetExtendedTcpTable(tcpTable, &tcpsize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            struct in_addr localAddr = { tcpTable->table[i].dwLocalAddr };
            struct in_addr remoteAddr = { tcpTable->table[i].dwRemoteAddr };
            char *procName = GetProcessName(tcpTable->table[i].dwOwningPid);

            printf("[TCPv4] Local: %s:%u  Remote: %s:%u  PID: %lu  Process: %s  State: %s\n",
                   inet_ntoa(localAddr),
                   ntohs((u_short)tcpTable->table[i].dwLocalPort),
                   inet_ntoa(remoteAddr),
                   ntohs((u_short)tcpTable->table[i].dwRemotePort),
                   (unsigned long)tcpTable->table[i].dwOwningPid,
                   procName,
                   GetState(tcpTable->table[i].dwState));

            free(procName);
        }
    }

    if (GetExtendedTcpTable(v6tcpTable, &v6tcpsize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < v6tcpTable->dwNumEntries; i++) {
            char localaddr[INET6_ADDRSTRLEN], remoteaddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(v6tcpTable->table[i].ucLocalAddr), localaddr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(v6tcpTable->table[i].ucRemoteAddr), remoteaddr, INET6_ADDRSTRLEN);

            char *procName = GetProcessName(v6tcpTable->table[i].dwOwningPid);

            printf("[TCPv6] Local: %s:%u  Remote: %s:%u  PID: %u  Process: %s  State: %s\n",
                   localaddr,
                   ntohs((u_short)v6tcpTable->table[i].dwLocalPort),
                   remoteaddr,
                   ntohs((u_short)v6tcpTable->table[i].dwRemotePort),
                   v6tcpTable->table[i].dwOwningPid,
                   procName,
                   GetState(v6tcpTable->table[i].dwState));

            free(procName);
        }
    }

cleanup:
    if (tcpTable) free(tcpTable);
    if (v6tcpTable) free(v6tcpTable);
}

void UDP_snapshot() {
    PMIB_UDPTABLE_OWNER_PID v4table = NULL;
    PMIB_UDP6TABLE_OWNER_PID v6table = NULL;
    DWORD v4size = 0, v6size = 0;

    if (GetExtendedUdpTable(NULL, &v4size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return;
    if (GetExtendedUdpTable(NULL, &v6size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) != ERROR_INSUFFICIENT_BUFFER) return;

    v4table = (PMIB_UDPTABLE_OWNER_PID)malloc(v4size);
    v6table = (PMIB_UDP6TABLE_OWNER_PID)malloc(v6size);

    if (!v4table || !v6table) goto cleanup;

    if (GetExtendedUdpTable(v4table, &v4size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < v4table->dwNumEntries; i++) {
            struct in_addr localAddr = { v4table->table[i].dwLocalAddr };
            char *procName = GetProcessName(v4table->table[i].dwOwningPid);

            printf("[UDPv4] Local: %s:%u  PID: %u  Process: %s\n",
                   inet_ntoa(localAddr),
                   ntohs((u_short)v4table->table[i].dwLocalPort),
                   v4table->table[i].dwOwningPid,
                   procName);

            free(procName);
        }
    }

    if (GetExtendedUdpTable(v6table, &v6size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
        for (DWORD i = 0; i < v6table->dwNumEntries; i++) {
            char localAddr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(v6table->table[i].ucLocalAddr), localAddr, INET6_ADDRSTRLEN);
            char *procName = GetProcessName(v6table->table[i].dwOwningPid);

            printf("[UDPv6] Local: %s:%u  ScopeID: %u  PID: %u  Process: %s\n",
                   localAddr,
                   ntohs((u_short)v6table->table[i].dwLocalPort),
                   ntohs((u_short)v6table->table[i].dwLocalScopeId),
                   v6table->table[i].dwOwningPid,
                   procName);

            free(procName);
        }
    }

cleanup:
    if (v4table) free(v4table);
    if (v6table) free(v6table);
}

DWORD WINAPI TCP_table_thread(LPVOID Param) {
    while (1) {
        TCP_snapshot();
        Sleep(5000); 
    }
    return 0;
}

DWORD WINAPI UDP_table_thread(LPVOID Param) {
    while (1) {
        UDP_snapshot();
        Sleep(2000); 
    }
    return 0;
}

