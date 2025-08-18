#include <stdio.h>
#include <pcap.h>
#include <windows.h>
#include <stdlib.h>

#include "Third_party/cjson.h"
#include "RegistryMonitor/registry.h"

HKEY mapRootKey(const char *root) {
    if (strcmp(root, "HKEY_CURRENT_USER") == 0) return HKEY_CURRENT_USER;
    if (strcmp(root, "HKEY_LOCAL_MACHINE") == 0) return HKEY_LOCAL_MACHINE;
    return NULL;
}

char *get_network_adapter( cJSON *json) {
    if (!json) {
        printf("Error: Failed to parse JSON\n");
        return NULL;
    }

    const cJSON *adapter = cJSON_GetObjectItem(json, "adapter");
    if (!cJSON_IsString(adapter) || adapter->valuestring == NULL) {
        printf("Error: 'adapter' key not found in config.json\n");
        cJSON_Delete(json);
        return NULL;
    }

    char *value = malloc(strlen(adapter->valuestring) + 1);
    if (!value) {
        cJSON_Delete(json);
        return NULL;
    }
    strcpy(value, adapter->valuestring);
    return value;
}

wchar_t **get_directories(cJSON *json){
    if (!json) {
        printf("Error: Failed to parse JSON\n");
        return NULL;
    }

    const cJSON *dir = cJSON_GetObjectItem(json, "directories");
    if (!cJSON_IsArray(dir)) {
        printf("Error getting object from json file\n");
        return NULL;
    }
    
    int len = cJSON_GetArraySize(dir);
    wchar_t **directories = malloc(sizeof(wchar_t *) * (len+1));

    if (!directories) {
        perror("Error in memory allocation \n");
        return NULL;
    }
    for(int i=0;i<len;i++){
        cJSON *val = cJSON_GetArrayItem(dir,i);
        if (cJSON_IsString(val) && val->valuestring != NULL) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, val->valuestring, -1, NULL, 0);
            directories[i] = malloc(sizeof(wchar_t)* wlen);
             MultiByteToWideChar(CP_UTF8, 0, val->valuestring, -1, directories[i], wlen);
        }
        else{
            directories[i] = NULL;
        }
    }
    directories[len] = NULL;
    return directories;
}

REG_PARAM *get_keys(cJSON *json){
    if(!json){
        printf("Error: Failed to parse JSON\n");
        return NULL;
    }

    const cJSON *keys = cJSON_GetObjectItem(json, "keys");
    if(!keys){
        printf("Error: Failed to parse JSON object\n");
        return NULL;
    }
    if(!cJSON_IsArray(keys)){
        printf("Error: Failed to parse JSON object\n");
        return NULL;
    }
    int keycount = cJSON_GetArraySize(keys);

    REG_PARAM *p = malloc(sizeof(REG_PARAM));
    if(!p){
        printf("Error: Failed to allocate memory\n");
        return NULL;
    }
    p->monitors = calloc(keycount,sizeof(REG_MONITOR));
    if(!p->monitors){
        printf("Error: Failed to allocate memory\n");
        return NULL;
    }
    p->count = keycount;
    int validCount = 0;
    for (int i = 0; i < keycount; i++) {
        cJSON *entry = cJSON_GetArrayItem(keys, i);
        if (!entry) continue;

        cJSON *root = cJSON_GetObjectItem(entry, "root");
        cJSON *key  = cJSON_GetObjectItem(entry, "path");
        if (!cJSON_IsString(root) || !cJSON_IsString(key)) continue;

        HKEY hRoot = mapRootKey(root->valuestring);
        if (!hRoot) continue;

        int wlen = MultiByteToWideChar(CP_UTF8, 0, key->valuestring, -1, NULL, 0);
        if (wlen <= 0) continue;

        wchar_t *wpath = malloc(wlen * sizeof(wchar_t));
        if (!wpath) continue;

        MultiByteToWideChar(CP_UTF8, 0, key->valuestring, -1, wpath, wlen);

        p->monitors[validCount].rootKey = hRoot;
        p->monitors[validCount].subkey  = wpath;
        p->monitors[validCount].handle  = NULL;
        p->monitors[validCount].event   = NULL;
        validCount++;
    }

    p->count = validCount;
    return p;
    
}

int is_valid_directory(const char *path) {
    DWORD attr = GetFileAttributes(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

int is_valid_registry_key(const char *key_path) {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key_path, 0, KEY_READ, &hKey);
    if(result == ERROR_SUCCESS){
        RegCloseKey(hKey);
        return 1; 
    }
    return 0; 
}

char* add_path(){
    char buffer[512];

    while(1){
        printf("Enter the Path: ");
    size_t len = strlen(buffer);
        if(len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';

        if(is_valid_directory(buffer)) break;

        printf("Invalid input. Try again.\n");
    }

    char *input = (char*)malloc(strlen(buffer) + 1);
    if(input) strcpy(input, buffer);

    return input;
}

char* add_key(){
    char buffer[512];

    while(1){
        printf("Enter the KEY: ");
    size_t len = strlen(buffer);
        if(len > 0 && buffer[len - 1] == '\n') buffer[len - 1] = '\0';

        if(is_valid_registry_key(buffer)) break;

        printf("Invalid input. Try again.\n");
    }

    char *input = (char*)malloc(strlen(buffer) + 1);
    if(input) strcpy(input, buffer);

    return input;
}

char* select_Adapter(){
    pcap_if_t *alldev, *dev;
    char errbuffer[PCAP_ERRBUF_SIZE];

    if(pcap_findalldevs(&alldev,errbuffer) == -1){
        printf("Error getting list of network adapters (%s)\n",errbuffer);
        return NULL;
    }
    int choise,index = 1;
    printf("Available Network Adapters: \n");
    for(dev = alldev; dev ; dev = dev->next){
        if(dev->description) {
            printf("[%d] %s %s\n", index++,dev->name, dev->description); 
        } else {
            printf("[%d] %s\n", index++, dev->name); 
        }
    }
    while(1){
        printf("Enter the adapter number: ");
        if(scanf("%d",&choise) != 1 || choise < 1 || choise >= index){
            printf("Invalid input. Try again. \n");
            while(getchar() != '\n');
            continue;
        }
        break;
    }
    int i = 1;
    char *selected_adapter = NULL;
    for(dev = alldev; dev ;dev = dev->next){
        if(i == choise ){
            const char *desc = dev->name;
            selected_adapter = (char *) malloc(strlen(desc)+ 1);
            if(selected_adapter){
                strcpy(selected_adapter, desc);
            }
            break;
        }
        i++;
    }
    pcap_freealldevs(alldev);
    return selected_adapter;
}
