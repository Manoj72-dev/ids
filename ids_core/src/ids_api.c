#include "../include/ids_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static pthread_t capture_thread;
volatile int stop_flag = 0;

void *capture_thread_func(void *arg);

int ids_start(const char *iface){
    stop_flag = 0;
    printf("Starting\n");
    char *iface_dup = strdup(iface);
    if(pthread_create(&capture_thread, NULL, capture_thread_func, iface_dup) != 0){
        return -1;
    }
    return 0;
}

int ids_stop(void){
    stop_flag = 1;
    return 0;
}

int ids_get_alert_count(void){
    return 0;
}

int ids_pop_alert(char *buffer, int bufsize){
    snprintf(buffer, bufsize, "NO_ALERTS");
    return 0;
}

