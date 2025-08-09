#include<winsock2.h>
#include<windows.h>
#include<iphlpapi.h>
#include<ws2tcpip.h>
#include<stdio.h>
#include<psapi.h>
#include<tchar.h>

char *GetState(DWORD par){
    int val = (int)par;
    switch(val){
        case 1:
            return "CLOSED";
            break;
        case 2:
            return "LISTEN";
            break;
        case 3:
            return "SYN-SENT";
            break;
        case 4:
            return "SYN-RECIVED";
            break;
        case 5:
            return "ESTABLISHED";
            break;
        case 6:
            return "FIN-WAIT-1";
            break;
        case 7:
            return "FIN-WAIT-2";
            break;
        case 8:
            return "CLOSE-WAIT";
            break;
        case 9:
            return "CLOSING";
            break;
        case 10:
            return "LAST-ACK";
            break;
        case 11:
            return "TIME-WAIT";
            break;
        case 12:
            return "DELETE TCB";
            break;
        default:
            return NULL;
    }
    return NULL;
}

char *GetProcessName(DWORD pid){
    if (pid == 4) {
        char *systemName = malloc(7);
        strcpy(systemName, "System");
        return systemName;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return NULL;
    }

    char fullPath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!QueryFullProcessImageNameA(hProcess, 0, fullPath, &size)) {
        CloseHandle(hProcess);
        return NULL;
    }
    CloseHandle(hProcess);

    char *baseName = strrchr(fullPath, '\\');
    if (baseName) baseName++;
    else baseName = fullPath;

    char *result = malloc(strlen(baseName) + 1);
    if (result) strcpy(result, baseName);
    return result;
}


DWORD WINAPI TCP_table(LPVOID Param){
    PMIB_TCPTABLE_OWNER_PID tcpTable=NULL;
    PMIB_TCP6TABLE_OWNER_PID  v6tcpTable=NULL;
    DWORD tcpsize =0,v6tcpsize = 0;
    DWORD retval, v6val;

    retval = GetExtendedTcpTable(NULL,&tcpsize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    v6val = GetExtendedTcpTable(NULL, &v6tcpsize,TRUE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0);
    if(retval == ERROR_INSUFFICIENT_BUFFER){
        printf("Getting buffer size\n");
    }
    
    tcpTable = (PMIB_TCPTABLE_OWNER_PID) malloc(tcpsize);
    v6tcpTable = (PMIB_TCP6TABLE_OWNER_PID) malloc(v6tcpsize);

    retval = GetExtendedTcpTable(tcpTable,&tcpsize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    v6val = GetExtendedTcpTable(v6tcpTable, &v6tcpsize,TRUE,AF_INET6,TCP_TABLE_OWNER_PID_ALL,0);

    for(DWORD i = 0; i < tcpTable->dwNumEntries;i++){
        char state_info[1024];
        struct in_addr localAddr, remoteAddr;
        localAddr.S_un.S_addr = tcpTable->table[i].dwLocalAddr;
        remoteAddr.S_un.S_addr = tcpTable->table[i].dwRemoteAddr;

        char *procName = GetProcessName(tcpTable->table[i].dwOwningPid);
        sprintf(state_info,"Local: %s:%u  Remote: %s:%u  PID: %lu ProcessName: %s  State: %s\n",
               inet_ntoa(localAddr),
               ntohs((u_short)tcpTable->table[i].dwLocalPort),
               inet_ntoa(remoteAddr),
               ntohs((u_short)tcpTable->table[i].dwRemotePort),
               tcpTable->table[i].dwOwningPid,
               procName,
               GetState(tcpTable->table[i].dwState));
        printf("%s\n ",state_info);
    }

    for(DWORD i=0;i<v6tcpTable->dwNumEntries;i++){
        char state_info[1024];
        char localaddr[INET6_ADDRSTRLEN];
        char remoteaddr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6,&(v6tcpTable->table[i].ucRemoteAddr), remoteaddr, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6,&(v6tcpTable->table[i].ucLocalAddr) ,localaddr,INET6_ADDRSTRLEN);
        
        char *proname =  GetProcessName(v6tcpTable->table[i].dwOwningPid);
        sprintf(state_info,"Local: %s:%u  LocalScope: %u Remote: %s:%u RemoteScope: %u PID: %u ProcessName: %s State: %s\n",
            localaddr,
            ntohs((u_short)v6tcpTable->table[i].dwLocalPort),
            ntohs((u_short)v6tcpTable->table[i].dwLocalScopeId),
            remoteaddr,
            ntohs((u_short)v6tcpTable->table[i].dwRemotePort),
            ntohs((u_short)v6tcpTable->table[i].dwRemoteScopeId),
            v6tcpTable->table[i].dwOwningPid,
            proname,
            GetState(v6tcpTable->table[i].dwState)
        );
        printf("%s\n",state_info);
    }


    free(tcpTable);
    return 0;
}


int main(){
    DWORD ThreadId;
    HANDLE Thread1 = CreateThread(NULL,0,TCP_table,NULL,0,&ThreadId);
    WaitForSingleObject(Thread1,INFINITE);
    CloseHandle(Thread1);
}

