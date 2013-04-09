#ifndef _FAIRPORT_CONTROL_H_
#define _FAIRPORT_CONTROL_H_
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

// Network
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>

#include <pthread.h>
#include "debugp.h"

#include "session.h"
#include "../config.h"
#include "tcp.h"
#include "fairport.h"
#include "audio.h"
//#include "hairtunes.h"

struct listening_thread_arg {
	char *port;
};
struct client_package {
	int fd;
	char *client_instance;
	char *dacp_id;
	char *active_remote;
	char *rtpmap;
	int  cseq;
	int reject;
};
struct client_context {
	struct sockaddr_in peer;
	int  fd;
	char *server_session;
};
struct body_keypair {
	char *key;
	char *value;
};
struct body_data {
	int count;
	struct body_keypair *keypairs;
};

int create_listening_thread( char *port );

char *create_server_session(void);
void *pthread_client_handler( void *arg );
void *pthread_tcp_connection_handler( void *arg );
void handle_new_tcp_connection( int socket );
void *listening_thread_func( void *arg );
int create_socket( char *port, int max_connection_queue );
int handle_tcp_message( struct tcp_message *message, struct client_context *ctx, int reject );

unsigned char *unbase64( unsigned char *input, int length);
char *base64(const unsigned char *input, int length);
char *apple_respond( char *apple_challenge, unsigned char *ipbin, int ipbinlen );
char *mallostrcpy( char *string );

RSA *private_key;
void load_private_key( char *file );
struct body_data *parse_body_keys( char *body );
void load_announce_params_into_session( struct body_data *data, session_t *sess );
void free_body_data( struct body_data *data );

#endif
