#ifndef _H_DTLS_
#define _H_DTLS_

#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>

#define DTLS_SERVER_NO_ERROR            0x1000
#define DTLS_SERVER_INVALID_CERT        DTLS_SERVER_NO_ERROR + 0x01
#define DTLS_SERVER_INVALID_KEY         DTLS_SERVER_NO_ERROR + 0x02
#define DTLS_SERVER_BAD_ADDR            DTLS_SERVER_NO_ERROR + 0x03
#define DTLS_SERVER_REALL_PROBLEM       DTLS_SERVER_NO_ERROR + 0x04
#define DTLS_SERVER_FAIL_KEYGEN         DTLS_SERVER_NO_ERROR + 0x05
#define DTLS_SERVER_INVALID_CLIENT_ADDR DTLS_SERVER_NO_ERROR + 0x06
#define DTLS_SERVER_INVALID_COOKIE_SECR DTLS_SERVER_NO_ERROR + 0x07
#define DTLS_SERVER_INVALID_COOKIE_SIZE DTLS_SERVER_NO_ERROR + 0x08
#define DTLS_SERVER_INVALID_COOKIE_FMT  DTLS_SERVER_NO_ERROR + 0x09
#define DTLS_SERVER_UNABLE_ACCEPT_CONN  DTLS_SERVER_NO_ERROR + 0x10

#define DTLS_CLIENT_NO_ERROR            0x2000
#define DTLS_CLIENT_BAD_ADDR            DTLS_CLIENT_NO_ERROR + 0x01
#define DTLS_CLIENT_REALL_PROBLEM       DTLS_CLIENT_NO_ERROR + 0x02

#define DTLS_SERVER_DEFAULT_CHIPER_LIST "TLSv1.2:TLSv1.0"

typedef union dtls_connection_u {
  struct sockaddr_storage storage;  // connection info (ipv6 or ipv4)
  struct sockaddr_in      ipv4;
  struct sockaddr_in6     ipv6;
} dtls_connection_u;

typedef struct dtls_connection_info_s {
  SSL*              ssl;
  int*              sock;
  dtls_connection_u client_addr;
  dtls_connection_u server_addr;
} dtls_connection_info_s;

#endif  // _H_DTLS_