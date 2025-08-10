#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <sddl.h>

int GetProcessUser(DWORD pid, char *userName, DWORD userNameSize) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return 0;

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        CloseHandle(hProcess);
        return 0;
    }

    DWORD size;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    PTOKEN_USER ptu = (PTOKEN_USER)malloc(size);

    if (!GetTokenInformation(hToken, TokenUser, ptu, size, &size)) {
        free(ptu);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return 0;
    }

    char name[256], domain[256];
    DWORD nameSize = sizeof(name);
    DWORD domainSize = sizeof(domain);
    SID_NAME_USE sidType;

    if (LookupAccountSidA(NULL, ptu->User.Sid, name, &nameSize, domain, &domainSize, &sidType)) {
        snprintf(userName, userNameSize, "%s\\%s", domain, name);
    } else {
        strcpy(userName, "UNKNOWN");
    }

    free(ptu);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    return 1;
}



char *GetProcessPath(DWORD pid){
    if (pid == 4) {
        char *systemName = _strdup("System");
        return systemName;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) return _strdup("Access Denied");



    char fullPath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!QueryFullProcessImageNameA(hProcess, 0, fullPath, &size)) {
        CloseHandle(hProcess);
        return _strdup("Unknown");
    }



    CloseHandle(hProcess);
    char *result = malloc(strlen(fullPath)+1);
     if (result) strcpy(result, fullPath);
    return result;
}

DWORD WINAPI GetProcesses(LPVOID Para){
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Snapshot failed.\n");
        return 1;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char *Pname =  GetProcessPath(pe32.th32ProcessID);
            char user[256];
            GetProcessUser(pe32.th32ProcessID, user, sizeof(user)); 
            printf("PID: %lu  Name: %s ParentID: %lu Path: %s User: %s\n", 
                pe32.th32ProcessID, 
                pe32.szExeFile, 
                pe32.th32ParentProcessID,
                Pname,
                user);
            free(Pname);
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        printf("Process32First failed.\n");
    }

    CloseHandle(hSnapshot);
    return 0;
}

int main(){
    DWORD Threadid;
    HANDLE hProcess = CreateThread(NULL,0,GetProcesses,NULL,0,&Threadid);
    if(hProcess == NULL){
        printf("Failed to create thread \n");
        return 1;
    }
    WaitForSingleObject(hProcess,INFINITE);
    CloseHandle(hProcess);
    return 0;
}