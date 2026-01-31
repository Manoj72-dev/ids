#ifndef ALERTS_H
#define ALERTS_H

int alerts_push(const char *msg);
int alerts_get_count(void);
int alerts_pop(char *buffer, int bufsize);

#endif
