#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>
#include <sddl.h>

#include "process.h"
#include "../Common/global.h"

int GetProcessUser(DWORD pid, char *userName, DWORD userNameSize) {

    HANDLE hProcess = NULL, hToken = NULL;
    PTOKEN_USER ptu =NULL;
    int success = 0;

    hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) goto cleanup;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) goto cleanup;

    DWORD size;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &size);
    ptu = (PTOKEN_USER)malloc(size);

    if (!GetTokenInformation(hToken, TokenUser, ptu, size, &size)) goto cleanup;

    char name[256], domain[256];
    DWORD nameSize = sizeof(name);
    DWORD domainSize = sizeof(domain);
    SID_NAME_USE sidType;

    if (LookupAccountSidA(NULL, ptu->User.Sid, name, &nameSize, domain, &domainSize, &sidType)) 
        snprintf(userName, userNameSize, "%s\\%s", domain, name);
    else 
        strcpy(userName, PROCESS_NAME_UNKNOWN);

    success =1;

cleanup:
    if (ptu) free(ptu);
    if (hToken) CloseHandle(hToken);
    if (hProcess) CloseHandle(hProcess);
    return success;
}



char *GetProcessPath(DWORD pid){
    if (pid == 4 )  
        return _strdup(PROCESS_NAME_SYSTEM);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) return _strdup(PROCESS_ACCESS_DENIED);

    char fullPath[MAX_PATH];
    DWORD size = MAX_PATH;

    if (!QueryFullProcessImageNameA(hProcess, 0, fullPath, &size)) {
        CloseHandle(hProcess);
        return _strdup(PROCESS_NAME_UNKNOWN);
    }

    CloseHandle(hProcess);
    char *result = malloc(strlen(fullPath)+1);
    if (result) strcpy(result, fullPath);
    return result;
}

void LogProcessInfo(DWORD pid, const char *exe, DWORD parent, const char *path, const char *user) {
    printf("PID: %lu  Name: %s  ParentID: %lu  Path: %s  User: %s\n",
           pid, exe, parent, path, user);

}

void EnumerateProcesses(){
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnapshot == INVALID_HANDLE_VALUE){
        printf("Snapshot Fail\n");
        return;
    }
    PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char *Ppath = GetProcessPath(pe32.th32ProcessID);
            char user[256];
            GetProcessUser(pe32.th32ProcessID, user, sizeof(user));
            LogProcessInfo(pe32.th32ProcessID, pe32.szExeFile, pe32.th32ParentProcessID, Ppath, user);
            free(Ppath);
        } while (Process32Next(hSnapshot, &pe32));
    } else {
        printf("Process32First failed.\n");
    }
    CloseHandle(hSnapshot);
}

DWORD WINAPI Process_monitor_thread(LPVOID Param){
    while(1){
        EnumerateProcesses();
        Sleep(5000);
    }
    return 0;
}
