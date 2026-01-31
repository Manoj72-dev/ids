#include "../include/alerts.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_ALERTS 1024
#define ALERT_MSG_SIZE 256

static char alert_queue[MAX_ALERTS][ALERT_MSG_SIZE];
static int head = 0, tail = 0;
int alerts_push(const char *msg){
    strncpy(alert_queue[tail], msg, ALERT_MSG_SIZE-1);
    tail = (tail + 1)% MAX_ALERTS;
    if (tail == head) 
        head = (head +1) %MAX_ALERTS;
    return 0;
}

int alerts_get_count(void){
    if(tail >= head)
        return tail - head;
    return MAX_ALERTS - head + tail;
}

int alerts_pop(char *buffer, int bufsize){
    if(head == tail) return 0;
    strncpy(buffer, alert_queue[head], bufsize - 1);
    head = (head -1) % MAX_ALERTS;
    return 1;
}