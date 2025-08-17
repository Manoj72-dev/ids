#include <stdio.h>
#include <pcap.h>
#include <windows.h>
#include <stdlib.h>

#include "Third_party/cjson.h"


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

char* get_path(){
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

char* get_key(){
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
