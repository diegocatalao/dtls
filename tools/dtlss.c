#include <arpa/inet.h>
#include <errno.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "dtls.h"
#include "logger.h"

#define CERTPATH             "assets/server-cert.pem"
#define KEYPATH              "assets/server-key.pem"
#define COOKIE_SECRET_LENGTH 16

static u_char   _cookie_secret[COOKIE_SECRET_LENGTH];
static bool     _cookie_secret_started = false;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

int generate_cookie(SSL* ssl, u_char* cookie, uint32_t* ncookie) {
  DEBUG("Received a cookie generation request");

  int status = DTLS_SERVER_NO_ERROR;

  u_char*  takeoff = NULL;  // the result of client ip address and port
  uint32_t ntakeoff = 0;    // the size of result takeoff

  u_char   flight[EVP_MAX_MD_SIZE];  // the hashed key generated from server
  uint32_t nflight = 0;              // the sizeof of generated key

  dtls_connection_u client_addr;  // client address information

  if (!_cookie_secret_started) {
    if (!RAND_bytes(_cookie_secret, COOKIE_SECRET_LENGTH)) {
      RAISE_STATUS(DTLS_SERVER_FAIL_KEYGEN, "Fail to generate the random key");
    }

    char* hexout = OPENSSL_buf2hexstr(_cookie_secret, COOKIE_SECRET_LENGTH);
    DEBUG("The server secret is '%s'", hexout);

    _cookie_secret_started = true;
  }

  // read the client connection information
  BIO_dgram_get_peer(SSL_get_rbio(ssl), &client_addr);

  // create the cookie from client ip address
  switch (client_addr.storage.ss_family) {
    case AF_INET:
      DEBUG("Get the size of ipv4 address from client");
      ntakeoff += sizeof(struct in_addr);
      break;
    case AF_INET6:
      DEBUG("Get the size of ipv6 address from client");
      ntakeoff += sizeof(struct in6_addr);
      break;
    default:
      RAISE_STATUS(DTLS_SERVER_INVALID_CLIENT_ADDR, "Invalid client addr");
      break;
  }

  // create the cookie from client port
  ntakeoff += sizeof(in_port_t);

  // now, alloc the buffer space from this information
  takeoff = (u_char*)OPENSSL_malloc(ntakeoff);

  if (takeoff == NULL) {
    RAISE_STATUS(DTLS_SERVER_REALL_PROBLEM, "Out of memory");
  }

  // set the client information to cookie space info
  switch (client_addr.storage.ss_family) {
    case AF_INET:
      DEBUG("Joing the information about ipv4 for the cookie");
      memcpy(takeoff, &client_addr.ipv4.sin_port, sizeof(in_port_t));
      memcpy(takeoff + sizeof(client_addr.ipv4.sin_port),
             &client_addr.ipv4.sin_addr, sizeof(in_addr_t));
      break;
    case AF_INET6:
      DEBUG("Joing the information about ipv6 for the cookie");
      memcpy(takeoff, &client_addr.ipv6.sin6_port, sizeof(in_port_t));
      memcpy(takeoff + sizeof(client_addr.ipv6.sin6_port),
             &client_addr.ipv4.sin_addr, sizeof(in6_addr_t));
      break;
    default:
      RAISE_STATUS(DTLS_SERVER_INVALID_CLIENT_ADDR, "Invalid client addr");
      break;
  }

  // generate the cookie for this session
  HMAC(EVP_sha1(), (const void*)_cookie_secret, COOKIE_SECRET_LENGTH,
       (const u_char*)takeoff, ntakeoff, flight, &nflight);

  // inform the client what`s the cookie needs to use
  memcpy(cookie, flight, nflight);
  *ncookie = nflight;

  DEBUG("The session cookie was %s", OPENSSL_buf2hexstr(flight, nflight));

clean_up:
  if (takeoff != NULL) {
    OPENSSL_free(takeoff);
  }

  return status == DTLS_SERVER_NO_ERROR;
}

int cookiever(SSL* ssl, const u_char* cookie, uint32_t ncookie) {
  DEBUG("Received a cookie verify request");

  int status = DTLS_SERVER_NO_ERROR;

  u_char*  takeoff = NULL;  // the result of client ip address and port
  uint32_t ntakeoff = 0;    // the size of result takeoff

  u_char   flight[EVP_MAX_MD_SIZE];  // the hashed key generated from server
  uint32_t nflight = 0;              // the sizeof of generated key

  dtls_connection_u client_addr;  // client address information

  if (!_cookie_secret_started) {
    RAISE_STATUS(DTLS_SERVER_INVALID_COOKIE_SECR, "Cookie is not initialized");
  }

  // read the client connection information
  BIO_dgram_get_peer(SSL_get_rbio(ssl), &client_addr);

  // recreate the cookie from client ip address
  switch (client_addr.storage.ss_family) {
    case AF_INET:
      DEBUG("Get the size of ipv4 address from client");
      ntakeoff += sizeof(struct in_addr);
      break;
    case AF_INET6:
      DEBUG("Get the size of ipv6 address from client");
      ntakeoff += sizeof(struct in6_addr);
      break;
    default:
      RAISE_STATUS(DTLS_SERVER_INVALID_CLIENT_ADDR, "Invalid client addr");
      break;
  }

  // create the cookie from client port
  ntakeoff += sizeof(in_port_t);

  // now, alloc the buffer space from this information
  takeoff = (u_char*)OPENSSL_malloc(ntakeoff);

  if (takeoff == NULL) {
    RAISE_STATUS(DTLS_SERVER_REALL_PROBLEM, "Out of memory");
  }

  // set the client information to cookie space info
  switch (client_addr.storage.ss_family) {
    case AF_INET:
      DEBUG("Joing the information about ipv4 for the cookie");
      memcpy(takeoff, &client_addr.ipv4.sin_port, sizeof(in_port_t));
      memcpy(takeoff + sizeof(client_addr.ipv4.sin_port),
             &client_addr.ipv4.sin_addr, sizeof(in_addr_t));
      break;
    case AF_INET6:
      DEBUG("Joing the information about ipv6 for the cookie");
      memcpy(takeoff, &client_addr.ipv6.sin6_port, sizeof(in_port_t));
      memcpy(takeoff + sizeof(client_addr.ipv6.sin6_port),
             &client_addr.ipv4.sin_addr, sizeof(in6_addr_t));
      break;
    default:
      RAISE_STATUS(DTLS_SERVER_INVALID_CLIENT_ADDR, "Invalid client addr");
      break;
  }

  // generate the cookie for this session
  HMAC(EVP_sha1(), (const void*)_cookie_secret, COOKIE_SECRET_LENGTH,
       (const u_char*)takeoff, ntakeoff, flight, &nflight);

  if (ncookie != nflight) {
    INFO("Calculated cookie size is %d and received is %d", ncookie, ntakeoff);
    RAISE_STATUS(DTLS_SERVER_INVALID_COOKIE_SIZE, "Invalid cookie size");
  }

  if (memcmp(flight, cookie, nflight) != 0) {
    RAISE_STATUS(DTLS_SERVER_INVALID_COOKIE_FMT, "Invalid received cookie");
  }

  DEBUG("The session check cookie was %s", OPENSSL_buf2hexstr(flight, nflight));

clean_up:
  if (takeoff != NULL) {
    OPENSSL_free(takeoff);
  }

  return status == DTLS_SERVER_NO_ERROR;
}

int main(int argc, char** argv) {
  int status = DTLS_SERVER_NO_ERROR;

  int       sock;
  const int is_reusable = true;
  const int isnt_reusable = false;

  struct timeval timeout;

  SSL_CTX*          context;      // ssl context configuration
  dtls_connection_u server_addr;  // server address information
  dtls_connection_u client_addr;  // client address information

  char* laddr = argv[1];        // localhost address
  int   lport = atoi(argv[2]);  // local port destination
  char  buffer[1024];           // the message buffer

  INFO("DTLS server will be started at '%s:%d'", laddr, lport);

  memset(&server_addr, 0, sizeof(struct sockaddr_storage));
  memset(&client_addr, 0, sizeof(struct sockaddr_storage));

  if (laddr == NULL || strlen(laddr) == 0) {
    // Set up IPv6 with any address (::) and specified port

    // Set address family to IPv6
    server_addr.ipv6.sin6_family = AF_INET6;
    // Set size of sockaddr_in6
    server_addr.ipv6.sin6_len = sizeof(struct sockaddr_in6);
    // Use "any" IPv6 address (::)
    server_addr.ipv6.sin6_addr = in6addr_any;
    // Set port number (convert to network byte order)
    server_addr.ipv6.sin6_port = htons(lport);
  } else if (inet_pton(AF_INET, laddr, &server_addr.ipv4.sin_addr) == 1) {
    // If laddr is a valid IPv4 address

    // Set address family to IPv4
    server_addr.ipv4.sin_family = AF_INET;
    // Set size of sockaddr_in
    server_addr.ipv4.sin_len = sizeof(struct sockaddr_in);
    // Set port number (convert to network byte order)
    server_addr.ipv4.sin_port = htons(lport);
  } else if (inet_pton(AF_INET6, laddr, &server_addr.ipv6.sin6_addr) == 1) {
    // If laddr is a valid IPv6 address

    // Set address family to IPv6
    server_addr.ipv6.sin6_family = AF_INET6;
    // Set size of sockaddr_in6
    server_addr.ipv6.sin6_len = sizeof(struct sockaddr_in6);
    // Set port number (convert to network byte order)
    server_addr.ipv6.sin6_port = htons(lport);
  } else {
    // If laddr is not a valid IPv4 or IPv6 address
    // Raise error with invalid address status
    RAISE_STATUS(DTLS_SERVER_BAD_ADDR, "Invalid IPv4/IPv6 address");
  }

  // start the ssl support and all crypto algorithms
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();
  OPENSSL_init_crypto(0, NULL);

  // creates a new SSL context for DTLS and disables session caching
  context = SSL_CTX_new(DTLS_server_method());
  SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_cipher_list(context, DTLS_SERVER_DEFAULT_CHIPER_LIST);

  // load and check if certificate exists
  if (!SSL_CTX_use_certificate_file(context, CERTPATH, SSL_FILETYPE_PEM)) {
    RAISE_STATUS(DTLS_SERVER_INVALID_CERT, "Invalid certificate file");
  }

  // load and check if private key exists
  if (!SSL_CTX_use_PrivateKey_file(context, KEYPATH, SSL_FILETYPE_PEM)) {
    RAISE_STATUS(DTLS_SERVER_INVALID_KEY, "Invalid private key file");
  }

  // check the integrity of private key
  if (!SSL_CTX_check_private_key(context)) {
    RAISE_STATUS(DTLS_SERVER_INVALID_KEY, "Invalid private key file");
  }

  // read the incoming data during TLS
  SSL_CTX_set_read_ahead(context, true);

  // set the cookie generator callback
  SSL_CTX_set_cookie_generate_cb(context, generate_cookie);

  // set the cookie verification callback
  SSL_CTX_set_cookie_verify_cb(context, cookiever);

  // create a server file descriptor socket
  sock = socket(server_addr.storage.ss_family, SOCK_DGRAM, 0);

  if (sock < 0) {
    RAISE_STATUS(DTLS_SERVER_REALL_PROBLEM, "Unable to create a sock");
  }

  // set this address as a reusable address
  // this is will be ignore the OS TIME_WAIT
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&is_reusable,
             (socklen_t)sizeof(is_reusable));
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&is_reusable,
             (socklen_t)sizeof(is_reusable));

  // the storage address for ipv6 or ipv4
  const struct sockaddr* sserver_addr = (const struct sockaddr*)&server_addr;

  if (server_addr.storage.ss_family == AF_INET) {
    // when the address is an ipv4

    // try to bind this address
    if (bind(sock, sserver_addr, sizeof(struct sockaddr_in))) {
      RAISE_STATUS(DTLS_SERVER_REALL_PROBLEM, "Unable to bind server");
    }
  } else {
    // when the address is an ipv6

    // set the socket specification for ipv6
    // IPV6_V6ONLY block ipv4 connections
    // and set this port as a not reusable port
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&isnt_reusable,
               sizeof(isnt_reusable));

    // try to bind this address
    if (bind(sock, sserver_addr, sizeof(struct sockaddr_in6))) {
      RAISE_STATUS(DTLS_SERVER_REALL_PROBLEM, "Unable to bind server");
    }
  }

  while (1) {
    BIO* bio = NULL;
    SSL* ssl = NULL;

    SSL_in_init(ssl);

    // clean all thrash memory for this client struct when was connected
    memset(&client_addr, 0, sizeof(struct sockaddr_storage));

    // creates a new connection for datagram protocol
    // ssl uses bio for receive any data from a dgram protocol
    // BIO_NOCLOSE: dont close this socket when bio was destroyed
    bio = BIO_new_dgram(sock, BIO_NOCLOSE);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    // set the timeout connection to 5 secs
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    // set the bio controller timeout interval
    // 2o arg: the recv timeout accepted for this connection
    // 3o arg: no argument for this operation
    // the timeout, struct timeval, for this time limit
    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    ssl = SSL_new(context);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

    DEBUG("Waiting for a new connection %p", ssl);

    while (DTLSv1_listen(ssl, (BIO_ADDR*)&client_addr) <= 0) {}

    SSL_accept(ssl);
    SSL_read(ssl, buffer, sizeof(buffer) / sizeof(buffer[0]));

    DEBUG("Received messsage: %s", buffer);

    // clear the buffer to receive a new message
    memset(buffer, 0, sizeof(buffer));
  }

clean_up:
  return status;
}