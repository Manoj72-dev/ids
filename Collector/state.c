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
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

    char fullPAth[MAX_PATH];
    DWORD size = MAX_PATH;

    if(!QueryFullProcessImageNameA(hProcess,0,fullPAth, &size)){
        CloseHandle(hProcess);
        return NULL;
    }

    CloseHandle(hProcess);

   

    char *result = malloc(strlen(fullPAth) + 1);
    if (result) strcpy(result, fullPAth);
    return result;

}

DWORD WINAPI Ipv4_table(LPVOID Param){
    PMIB_TCPTABLE_OWNER_PID tcpTable=NULL;
    DWORD tcpsize =0;
    DWORD retval;

    retval = GetExtendedTcpTable(NULL,&tcpsize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    tcpTable = (PMIB_TCPTABLE_OWNER_PID) malloc(tcpsize);

    retval = GetExtendedTcpTable(tcpTable,&tcpsize,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);

    for(DWORD i = 0; i < tcpTable->dwNumEntries;i++){
        char state_info[1024];
        struct in_addr localAddr, remoteAddr;
        localAddr.S_un.S_addr = tcpTable->table[i].dwLocalAddr;
        remoteAddr.S_un.S_addr = tcpTable->table[i].dwRemoteAddr;

        char *procName = GetProcessName(tcpTable->table[i].dwOwningPid);
        sprintf(state_info,"[%lu] Local: %s:%u  Remote: %s:%u  PID: %lu ProcessName: %s  State: %s\n",
               i,
               inet_ntoa(localAddr),
               ntohs((u_short)tcpTable->table[i].dwLocalPort),
               inet_ntoa(remoteAddr),
               ntohs((u_short)tcpTable->table[i].dwRemotePort),
               tcpTable->table[i].dwOwningPid,
               procName,
               GetState(tcpTable->table[i].dwState));
        printf("%s\n ",state_info);
    }
    free(tcpTable);
    return 0;
}


int main(){
    DWORD ThreadId;
    HANDLE Thread1 = CreateThread(NULL,0,Ipv4_table,NULL,0,&ThreadId);
    WaitForSingleObject(Thread1,INFINITE);
    CloseHandle(Thread1);
}

