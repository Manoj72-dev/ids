#include "sniffer.h"

#include<windows.h>
#include<pcap.h>


int main(){
    
    DWORD threadId1;
    HANDLE hThread1 = CreateThread(NULL,0,capture_packets,NULL,0,&threadId1) ;
    
    
    if(hThread1 == NULL){
        fprintf(stderr,"CreateThread Failed. Error: %lu\n",GetLastError());
        return 1;
    }

    WaitForSingleObject(hThread1,INFINITE);
    CloseHandle(hThread1);
    return 1;
}