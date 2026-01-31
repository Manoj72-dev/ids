#ifndef IDS_API_h
#define IDS_API_H

#ifdef __cplusplus
extern "C" {
#endif 

int ids_start(const char *iface );

int ids_stop(void);

int ids_get_alert_count(void);

int ids_pop_alert(char *buffer, int bufsize);

#ifdef __cplusplus
}

#endif

#endif