#include "global.h"
#include <time.h>
#include "../Third_party/cjson.h"

HANDLE hPipeNet = NULL;
HANDLE hPipeMon = NULL;
HANDLE hPipeErr = NULL;

CRITICAL_SECTION gPipeLock;

int safe_pipe_write(HANDLE hPipe, const char *msg){
    EnterCriticalSection(&gPipeLock);
    DWORD written;
    BOOL ok = WriteFile(hPipe,msg,(DWORD)strlen(msg),&written,NULL);
    LeaveCriticalSection(&gPipeLock);
    return ok ? 1 : 0;
}

void send_error(HANDLE hPipe, const char *msg, int code){
    cJSON *err = cJSON_CreateObject();
    cJSON_AddStringToObject(err,"type","error");
    cJSON_AddStringToObject(err,"message",msg);
    cJSON_AddNumberToObject(err,"code",code);
    cJSON_AddNumberToObject(err,"ts",(double)time(NULL));

    char *jsonStr = cJSON_PrintUnformatted(err);
    cJSON_Delete(err);

    if(jsonStr){
        safe_pipe_write(hPipe,jsonStr);
        free(jsonStr);
    }
}

void send_json(HANDLE hPipe, cJSON *json){
    char *jsonstr = cJSON_PrintUnformatted(json);
    if(jsonstr){
        safe_pipe_write(hPipe,jsonstr);
        free(jsonstr);
    }
    cJSON_Delete(json);
}