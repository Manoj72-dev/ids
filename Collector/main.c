#include "sniffer.h"
#include "file.h"

#include<windows.h>
#include<pcap.h>


int main(){
    DWORD threadId1[2];
    HANDLE hThread1[2];
    hThread1[0] = CreateThread(NULL,0,capture_packets,NULL,0,&threadId1[0]) ;
    hThread1[1] = CreateThread(NULL,0,moniter,NULL,0,&threadId1[0]) ;
    
    if(hThread1[0] == NULL || hThread1[1] == NULL){
        fprintf(stderr,"CreateThread Failed. Error: %lu\n",GetLastError());
        return 1;
    }

    WaitForMultipleObjects(2,hThread1,FALSE,INFINITE);
    CloseHandle(hThread1[0]);
    CloseHandle(hThread1[1]);
    return 1;
}