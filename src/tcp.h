#ifndef _FAIRPORT_TCP_H_
#define _FAIRPORT_TCP_H_
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

// Network
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <pthread.h>
#include "debugp.h"

#include "../config.h"

enum tcp_context {
	METHOD,
	HEADER_FIELD,
	HEADER_VALUE,
	BODY
};
struct header {
	char *field;
	char *value;
};
struct tcp_message {
	char *buffer;
	char *method;
	int num_headers;
	struct header **headers;
	char *body;
	int body_length;

	// these are for the parser's use only
	enum tcp_context ctx;
	int buffer_pos;
	char *field;
	char *value;
};

void tcp_message_init( struct tcp_message *message );
struct header *mkheader( char *field, char *value );
void tcp_message_add_header( struct tcp_message *msg, struct header *header );
void free_tcp_message( struct tcp_message *message );
void print_tcp_message( struct tcp_message *message );
void send_tcp_message( struct tcp_message *message, int fd );
char *get_value_by_field_name( struct tcp_message *message, char *field );
int tcp_parse( 
		char *inbuf, 
		int in_length, 
		char *outbuf, 
		struct tcp_message **msg );

#endif
