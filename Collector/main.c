#include "Network/sniffer.h"
#include "FileMonitor/file.h"
#include "Network/state.h"
#include "ProcessMonitor/process.h"
#include "RegistryMonitor/registry.h"
#include "Third_party/cjson.h"
#include "config.h"
#include "Common/global.h"

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

cJSON *get_json(){
    FILE *f = fopen("..\\Config\\config.json", "r");
    if (!f) {
        printf("Error: Could not open config.json\n");
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = malloc(len + 1);
    if (!data) {
        fclose(f);
        return NULL;
    }

    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);

    cJSON *json = cJSON_Parse(data);
    free(data);
    return json;
}


int main(){

    hPipeNet = CreateNamedPipe(
        "\\\\.\\pipe\\IDS_Network",
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        65536,   
        4096,    
        0,
        NULL
    );

    hPipeMon = CreateNamedPipe(
        "\\\\.\\pipe\\IDS_Monitor",
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        16384,
        4096,
        0,
        NULL
    );

    hPipeErr = CreateNamedPipe(
        "\\\\.\\pipe\\IDS_Error",
        PIPE_ACCESS_OUTBOUND,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        4096,
        4096,
        0,
        NULL
    );

     if (hPipeNet == INVALID_HANDLE_VALUE ||
        hPipeMon == INVALID_HANDLE_VALUE ||
        hPipeErr == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Failed to create named pipes. Error: %lu\n", GetLastError());
        return 1;
    }

    printf("[+] Named pipes created. Waiting for client connections...\n");

    ConnectNamedPipe(hPipeNet, NULL);
    ConnectNamedPipe(hPipeMon, NULL);
    ConnectNamedPipe(hPipeErr, NULL);

    printf("[+] Clients connected to named pipes.\n");

    cJSON *json = get_json();
    wchar_t **dir = get_directories(json);
    char *adapter = get_network_adapter(json);
    REG_PARAM *p = get_keys(json);
 
    DWORD threadId[6];
    HANDLE hThread[6];
    hThread[0] = CreateThread(NULL,0,capture_packets,adapter,0,&threadId[0]) ;
    hThread[1] = CreateThread(NULL,0,file_monitor_thread,dir,0,&threadId[1]) ;
    hThread[2] = CreateThread(NULL, 0, TCP_table_thread, NULL, 0, &threadId[2]);
    hThread[3] = CreateThread(NULL, 0, UDP_table_thread, NULL, 0, &threadId[3]);
    hThread[4] = CreateThread(NULL, 0, Process_monitor_thread,NULL, 0, &threadId[4]);
    hThread[5] = CreateThread(NULL, 0, registry_monitor_thread, p, 0, &threadId[5]); 
    for(int i=0;i<6;i++){
        if(hThread[i] == NULL){
            fprintf(stderr,"CreateThread Failed. Error: %lu\n",GetLastError());
            return 1;
        }
    }

    WaitForMultipleObjects(6,hThread,FALSE,INFINITE);
    for(int i=0;i<6;i++)
        CloseHandle(hThread[i]);
    
    return 1; 

}