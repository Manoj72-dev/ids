#ifndef CONFIG_H
#define CONFIG_H 

#include "Third_party/cjson.h"
#include <windows.h>

HKEY mapRootKey(const char *root);

char *get_network_adapter( cJSON *json);
wchar_t **get_directories(cJSON *json);
REG_PARAM *get_keys(cJSON *json);

int is_valid_directory(const char *path);
int is_valid_registry_key(const char *key_path);

char* add_path();
char* add_key();
char* select_Adapter();

#endif