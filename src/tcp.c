#ifndef _FAIRPORT_TCP_SOURCE_
#define _FAIRPORT_TCP_SOURCE_
#include "tcp.h"
#include <ctype.h>
#include <ctype.h>

void tcp_message_init( struct tcp_message *message )
{
	message->buffer = NULL;
	message->method = NULL;
	message->num_headers = 0;
	message->headers = NULL;
	message->body = NULL;
	message->body_length = 0;

	message->ctx = METHOD;
	message->buffer_pos = 0;
	message->field = NULL;
	message->value = NULL;
	return;
}
struct header *mkheader( char *field, char *value )
{
	struct header *header = malloc(sizeof(struct header));
	header->field = malloc(sizeof(char)*(strlen(field)+1));
	strcpy(header->field,field);
	header->value = malloc(sizeof(char)*(strlen(value)+1));
	strcpy(header->value,value);
	return header;
}
void tcp_message_add_header( struct tcp_message *msg, struct header *header )
{
	(msg->num_headers)++;
	msg->headers = realloc( 
			msg->headers, 
			sizeof(struct header*) * msg->num_headers );
	msg->headers[msg->num_headers-1] = header;
	
	debugp( DEBUGP_TCP, 10, 
			"tcp_message_add_header(%d) field=%s value=%s\n",
			msg->num_headers,
			msg->headers[msg->num_headers-1]->field,
			msg->headers[msg->num_headers-1]->value);
	
	return;
}
void free_tcp_message( struct tcp_message *message )
{
	for( int h = 0; h < message->num_headers; h++ )
	{
		free( message->headers[h]->field );
		free( message->headers[h]->value );
		free( message->headers[h] );
	}
	free( message->headers );
	free( message->buffer );
	free( message );
	return;
}
void print_tcp_message( struct tcp_message *message )
{
	debugp( DEBUGP_TCP, 0, "TCP Message:\n" );
	debugp( DEBUGP_TCP, 0, "%s\n", message->method );
	for( int h = 0; h < message->num_headers; h++ )
	{
		debugp( DEBUGP_TCP, 0, "%s: %s\n", 
				message->headers[h]->field,
				message->headers[h]->value
			  );
	}
	debugp( DEBUGP_TCP, 0, "Body: %*s\n", message->body_length, message->body );
	return;
}
void send_tcp_message( struct tcp_message *message, int fd )
{
	if(message==NULL)
		return;
	char buffer[1024];

	if( message->method != NULL )
	{
		strcpy( buffer, message->method );
		strcat( buffer, "\r\n" );
	}

	for( int h = 0; h < message->num_headers; h++ )
	{
		strcat( buffer, message->headers[h]->field );
	strcat( buffer, ": " );
		strcat( buffer, message->headers[h]->value );
		strcat( buffer, "\r\n" );
	}
	if(message->body != NULL)
	{
		strcat( buffer, message->body );
		strcat( buffer, "\r\n\r\n" );
	}
	else
		strcat( buffer, "\r\n" );

	debugp( DEBUGP_TCP, 4, "\nSending TCP Message:\n%s\n", buffer );

	int bytes = send( fd, buffer, strlen(buffer), 0 );
	debugp( DEBUGP_TCP, 4, "Sent %d bytes\n", bytes );

	return;
}
char *get_value_by_field_name( struct tcp_message *message, char *field )
{
	char *value = NULL;
	for( int h = 0; h < message->num_headers; h++ )
	{
		debugp( DEBUGP_TCP, 10, "message->headers[%d/%d]->field = %s; value = %s\n",h+1,message->num_headers, message->headers[h]->field, message->headers[h]->value );
		if(strcmp(field,message->headers[h]->field)==0)
		{
			value = message->headers[h]->value;
			break;
		}
	}
	debugp( DEBUGP_TCP, 10, "get_value_by_field_name(\"%s\") = %s\n", field, value );
	return value;
}
int tcp_parse( 
		char *in, 
		int in_length, 
		char *buffer, 
		struct tcp_message **msg )
{
	int done = 0;

	if( *msg == NULL )
	{
		*msg = malloc(sizeof(struct tcp_message));
		tcp_message_init( *msg );

		(*msg)->method = buffer;
	}
	char *b = buffer + (*msg)->buffer_pos;
	char *i = in;
	int l = in_length;

	while(l--)
	{
		*b = *i;

		switch((*msg)->ctx)
		{
			case METHOD:
				if( *b == '\n' )
				{
					if(*(b-1)=='\r')
						*(b-1) = '\0';
					else
						*b = '\0';
					
					(*msg)->field = b+1;
					(*msg)->ctx = HEADER_FIELD;
				}
				break;
			case HEADER_FIELD:
				if( *b == ':' )
				{
					*b = '\0';
					(*msg)->value = b+1;
					(*msg)->ctx = HEADER_VALUE;
				}
				else if( *b == '\n' )
				{
					if( (*msg)->body_length == 0 )
					{
						done = 1;
					}
					else
					{
						(*msg)->body = b+1;
						(*msg)->ctx = BODY;
					}
				}
				break;
			case HEADER_VALUE:
				if( *((*msg)->value) == ' ' )
					((*msg)->value)++;
				if( *b == '\n' )
				{
					if( *(b-1)=='\r')
						*(b-1) = '\0';
					else
						*b = '\0';

					tcp_message_add_header( *msg, mkheader((*msg)->field,(*msg)->value) );
					if( strcasecmp( (*msg)->field, "Content-Length" ) == 0 )
					{
						(*msg)->body_length = atoi( (*msg)->value );
					}

					(*msg)->field = b+1;
					(*msg)->ctx = HEADER_FIELD;
				}
				break;
			case BODY:
				if( ((*msg)->buffer_pos - ((*msg)->body-buffer)) == (*msg)->body_length - 1 )
				{
					*(b+1)='\0';
					done = 1;
				}
				break;
		}

		((*msg)->buffer_pos)++;
		b++;
		i++;
	}

	return done;
}
#endif
