#ifndef GLOBAL_H
#define GLOBAL_H

#include <windows.h>

#include "../Third_party/cjson.h"

extern HANDLE hPipeNet;   
extern HANDLE hPipeMon;  
extern HANDLE hPipeErr;   

extern CRITICAL_SECTION gPipeLock;

void safe_pip_write(HANDLE hPipe, const char *msg);

void send_json(HANDLE hPipe, cJSON *json);

void send_error(HANDLE hPipe, const char *msg, int code);

#endif