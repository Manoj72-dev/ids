#include "sniffer.h"
#include "file.h"
#include "state.h"
#include "process.h"

#include <windows.h>


int main(){
    DWORD threadId[4];
    HANDLE hThread[4];
    hThread[0] = CreateThread(NULL,0,capture_packets,NULL,0,&threadId[0]) ;
    hThread[1] = CreateThread(NULL,0,moniter,NULL,0,&threadId[1]) ;
    hThread[2] = CreateThread(NULL, 0, TCP_table_thread, NULL, 0, &threadId[2]);
    hThread[3] = CreateThread(NULL, 0, UDP_table_thread, NULL, 0, &threadId[3]);
    hThread[4] = CreateThread(NULL, 0, Process_monitor_thread,NULL, 0, &threadId[4]);
    for(int i=0;i<4;i++){
        if(hThread[i] == NULL){
            fprintf(stderr,"CreateThread Failed. Error: %lu\n",GetLastError());
            return 1;
        }
    }

    WaitForMultipleObjects(2,hThread,FALSE,INFINITE);
    for(int i=0;i<4;i++)
        CloseHandle(hThread[i]);
    return 1;
}