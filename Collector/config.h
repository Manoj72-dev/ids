#ifndef CONFIG_H
#define CONFIG_H 

#include "Third_party/cjson.h"
#include <windows.h>

char *get_network_adapter( cJSON *json);
int is_valid_directory(const char *path);
int is_valid_registry_key(const char *key_path);
char* get_path();
char* get_key();
char* select_Adapter();
#endif