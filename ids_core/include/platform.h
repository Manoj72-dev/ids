#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef unsigned char u_char;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
typedef unsigned char u_char;
#endif

#endif
