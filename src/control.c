#ifndef _FAIRPORT_CONTROL_SOURCE_
#define _FAIRPORT_CONTROL_SOURCE_
#include <pcre.h>
#include <assert.h>
#include <arpa/inet.h>
#include "control.h"
//#include "hairtunes.h"

static pthread_t listening_thread;

static int num_tcp_handlers = 0;
static pthread_t **tcp_handlers = NULL;
//static pthread_t main_tcp_thread;

static struct listening_thread_arg l_args;
extern char *apname;
static char *audio_jack_status = "connected";
static char *audio_jack_type = "analog";

static int we_are_streaming = 0;

extern char *start_task;
extern char *end_task;

int create_socket( char *port, int max_connection_queue )
{
	int sock;

	struct addrinfo hints, *res;
	memset( &hints, 0, sizeof(hints) );
	
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	getaddrinfo( NULL, port, &hints, &res );

	if( ( sock = socket( res->ai_family, res->ai_socktype, res->ai_protocol ) ) < 0 ) // only binds to first address returned; could do more
	{
		perror( "sock" );
		sock = -1;
	}

	//lose the pesky "Address already in use" error message
	int yes = 1;
	if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0 ) 
	{
		perror("setsockopt");
		sock = -1;
	}
	
	if( bind( sock, res->ai_addr, res->ai_addrlen ) < 0 )
	{
		perror("bind");
		sock = -1;
	}

	if( listen( sock, max_connection_queue ) < 0 )
	{
		perror("listen");
		sock = -1;
	}
	
	freeaddrinfo(res);

	return sock;
}
int create_listening_thread( char *port )
{
	l_args.port = port;
							

	pthread_create( &listening_thread, NULL, listening_thread_func, (void*)&l_args );
	return 0;
}
void *listening_thread_func( void *arg )
{
	struct listening_thread_arg *args = (struct listening_thread_arg*)arg;
	int tcp_socket = create_socket( args->port, 10 );

	struct timeval now;
	gettimeofday( &now, NULL );
	srand( now.tv_sec );

	while(1)
	{
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
		fd_set sset;
		FD_ZERO( &sset );
		FD_SET( tcp_socket,&sset );
		int highsock = tcp_socket + 1;
		int ready;
		ready = select( highsock, &sset, NULL, NULL, &timeout );

		if( (ready>0) && (errno!=EINTR) )
		{
			if( FD_ISSET( tcp_socket, &sset ) )
			{
				handle_new_tcp_connection(tcp_socket);
			}
		}
		else if( ready < 0 )
		{
			perror("select()");
			exit(-1);
		}
	}
	pthread_exit(NULL);
}
void handle_new_tcp_connection( int socket )
{
	// Network socket has a connection waiting
	debugp( DEBUGP_TCP, 8, "Network connection ready\n" );

	struct client_package *package = malloc(sizeof(struct client_package));

	package->client_instance = NULL;
	package->dacp_id = NULL;
	package->active_remote = NULL;
	package->rtpmap = NULL;
	package->reject = 0;

	struct sockaddr remotesock;
	socklen_t remotesock_size = sizeof(remotesock);

	if( ( package->fd = accept( socket, &remotesock, &remotesock_size ) ) > 0 )
	{
		num_tcp_handlers++;
		tcp_handlers = realloc( tcp_handlers, sizeof(pthread_t*)*num_tcp_handlers );
		tcp_handlers[num_tcp_handlers-1] = malloc(sizeof(pthread_t));

		if( pthread_create( tcp_handlers[num_tcp_handlers-1], NULL, pthread_tcp_connection_handler, (void*)package ) == 0 )
		{
			debugp( DEBUGP_TCP, 5, "Created thread\n" );
		}
		else
		{
			debugp( DEBUGP_TCP, 1, "Pthread create failed!\n" );
			free(package);
		}
	}
	return;
}

void *pthread_tcp_connection_handler( void *arg )
{
	session_t *session = NULL;
	struct client_package *package = (struct client_package*)arg;
	
	// Get our ip address
	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);
	char host_address[INET6_ADDRSTRLEN];
	getsockname( package->fd, (struct sockaddr*)&addr, &len );

	int ipbinlen = 0;
	unsigned char ipbin[6];

	if( addr.ss_family == AF_INET )
	{
		struct sockaddr_in *s = (struct sockaddr_in*)&addr;
		inet_ntop( AF_INET, &s->sin_addr, host_address, sizeof(host_address) );
		debugp( DEBUGP_TCP, 5, "Accepted connection. Our ip address: %s (%d)\n", host_address, package->fd );
		ipbinlen = 4;
		memcpy( ipbin, &s->sin_addr, ipbinlen );
	}
	else
	{
		debugp( DEBUGP_TCP, 0, "Error: IPv6 not implemented yet\n" );
		exit(-1);
	}
	
	struct sockaddr_storage peeraddr;
	socklen_t peerlen = sizeof(addr);
	char peer_address[INET6_ADDRSTRLEN];
	getpeername( package->fd, (struct sockaddr*)&peeraddr, &peerlen );

	if( peeraddr.ss_family == AF_INET )
	{
		struct sockaddr_in *s = (struct sockaddr_in*)&peeraddr;
		inet_ntop( AF_INET, &s->sin_addr, peer_address, sizeof(peer_address) );
		debugp( DEBUGP_TCP, 5, "Client address: %s\n", peer_address );
	}

	int bytes;
	char buffer[8193];
	struct tcp_message *parsed = NULL;
	while(1)
	{
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
		fd_set sset;
		FD_ZERO( &sset );
		FD_SET( package->fd,&sset );
		int highsock = package->fd + 1;

		int ready;
		ready = select( highsock, &sset, NULL, NULL, &timeout );
		if( ready < 0 )
		{
			debugp( DEBUGP_TCP, 0, "Error: select() returned %d\n", ready );
		}
		else if( ready > 0 )
		{
			if( FD_ISSET( package->fd, &sset ) )
			{
				char received[8193];
				bytes = recv( package->fd, received, 8192, 0 );
				if( bytes == 0 )
				{
					debugp( DEBUGP_TCP, 3, "%s closed connection\n", peer_address );
					break;
				}
				else if( tcp_parse(
							received,
							bytes,
							buffer,
							&parsed ) == 1 )
				{

					if(parsed==NULL)
						continue;

					print_tcp_message(parsed);
			
					int connection_close = 0;
					struct tcp_message *response = malloc(sizeof(struct tcp_message));
					tcp_message_init(response);
					response->method = "RTSP/1.0 200 OK";
				
					// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
					// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
//					if(session)
//					{
//						debugp( DEBUGP_TCP, 7, "control.h session %08X lock cc_mutex\n", session->id );
//						pthread_mutex_lock( session->cc_mutex );
//					}

					/** 
					 * Client instance
					 */
					if( package->client_instance == NULL )
					{
						char *client_instance = get_value_by_field_name( parsed, "Client-Instance" );
						if( client_instance != NULL )
						{
							package->client_instance = mallostrcpy( client_instance );
							debugp( DEBUGP_TCP, 6, "Set client-instance to: %s\n", package->client_instance );
						}
					}
					
					/** 
					 * DACP-ID
					 */
					if( package->dacp_id == NULL )
					{
						char *dacp_id = get_value_by_field_name( parsed, "DACP-ID" );
						if( dacp_id != NULL )
						{
							package->dacp_id = mallostrcpy( dacp_id );
							debugp( DEBUGP_TCP, 6, "Set DACP-ID to: %s\n", package->dacp_id );
						}
					}
					
					/** 
					 * Active Remote
					 */
					if( package->active_remote == NULL )
					{
						char *active_remote = get_value_by_field_name( parsed, "Active-Remote" );
						if( active_remote != NULL )
						{
							package->active_remote = mallostrcpy( active_remote );
							debugp( DEBUGP_TCP, 6, "Set Active-Remote to: %s\n", package->active_remote );
						}
					}
					
					/**
					 * CSeq
					 */
					char *cseq_str = malloc(sizeof(char)*10);
					char *cseq;
					if( ( cseq = get_value_by_field_name( parsed, "CSeq" ) ) != NULL )
						package->cseq = atoi(cseq);
					else
						package->cseq = 1;

					sprintf( cseq_str, "%d", package->cseq );
					tcp_message_add_header(response, mkheader("CSeq", cseq_str));

					/** 
					 * Session
					 */
					char *session_str;
					if( ( session_str = get_value_by_field_name( parsed, "Session" ) ) )
					{
						debugp( DEBUGP_TCP, 7, "Session identified as %s\n", session_str );
					
						if( ( session = find_session_by_str( session_str ) ) == NULL )
						{
							response->method = "RTSP/1.0 454 Session Not Found";
							connection_close = 1;
						}
						else
						{
							char session_str[128];
							sprintf( session_str, "%08X", session->id );
							tcp_message_add_header(response, mkheader("Session",session_str));
						}
					}

					/**
					 * Handle methods
					 */
					if( strncmp( parsed->method, "OPTIONS", 7 ) == 0 )
					{
						tcp_message_add_header(response, mkheader("Public", "ANNOUNCE, SETUP, RECORD, PAUSE, FLUSH, TEARDOWN, OPTIONS, GET_PARAMETER, SET_PARAMETER"));
					}
					else if( strncmp( parsed->method, "ANNOUNCE", 8 ) == 0 )
					{
						if( session == NULL )
						{
							session = create_session(30);
							memcpy( &session->remote_host, &peeraddr, sizeof(peeraddr) );
						}

						struct body_data *data = parse_body_keys( parsed->body );
						load_announce_params_into_session(data,session);
						free_body_data(data);

					}
					else if( strncmp( parsed->method, "SET_PARAMETER", 13 ) == 0 )
					{
						debugp( DEBUGP_TCP, 6, "Got SET_PARAMETER request; body=`%s'\n", parsed->body );
						double vol;
						if( sscanf( parsed->body, "volume: %lf", &vol ) == 1 )
						{
							debugp( DEBUGP_TCP, 5, "Parsed vol=%lf\n", vol );

							set_volume( session, vol );
						
						}
					}
					else if( strncmp( parsed->method, "SETUP", 5 ) == 0 )
					{
						if(package->reject) // If we are rejecting this client
						{
							response->method = "RTSP/1.0 453 Not Enough Bandwidth";
							connection_close = 1;
						}
						else
						{
							assert( session != NULL );
							
							char session_str[128];
							sprintf( session_str, "%08X", session->id );
							tcp_message_add_header(response, mkheader("Session",session_str));
							
							// Transport
							char *transport = get_value_by_field_name(parsed,"Transport");

							const char *pcre_err = NULL;
							int pcre_err_offset = 0;
							int pcre_ovectors[6];

							memset(pcre_ovectors,0,sizeof(pcre_ovectors));
							const char *cpregex = "control_port=(\\d+)";
							pcre *cpre = pcre_compile( cpregex, 0, &pcre_err, &pcre_err_offset, NULL );
							if( pcre_exec( cpre, NULL, transport, strlen(transport), 0, 0, pcre_ovectors, 6 ) == 2 )
							{
								char control_port[10];
								sprintf( control_port, "%.*s",
										pcre_ovectors[3] - pcre_ovectors[2],
										transport + pcre_ovectors[2] );
								//session->control_port = atoi(control_port);
								//debugp( DEBUGP_TCP, 7, "requested control_port = %d\n", session->control_port );
							}
							free(cpre);
							
							memset(pcre_ovectors,0,sizeof(pcre_ovectors));
							const char *tpregex = "timing_port=(\\d+)";
							pcre *tpre = pcre_compile( tpregex, 0, &pcre_err, &pcre_err_offset, NULL );
							if( pcre_exec( tpre, NULL, transport, strlen(transport), 0, 0, pcre_ovectors, 6 ) == 2 )
							{
								char timing_port[10];
								sprintf( timing_port, "%.*s",
										pcre_ovectors[3] - pcre_ovectors[2],
										transport + pcre_ovectors[2] );
								//session->timing_port = atoi(timing_port);
								//debugp( DEBUGP_TCP, 7, "requested timing_port = %d\n", session->timing_port );
							}
							free(tpre);
							//session->server_port = session->control_port - 1;

							char tp[1024];
							
							// XXX These are static for now
							sprintf( tp, "RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d;server_port=%d",
									6001,
									6002,
									6000
									);
							tcp_message_add_header(response, mkheader( "Transport", tp ));

							//debugp( DEBUGP_TCP, 7, "final ports: %s\n", tp );
						}
					}
					else if( strncmp( parsed->method, "RECORD", 6 ) == 0 ) // Setup and start streaming
					{
						// Start task
						int f = fork();
						if( f == 0 )
						{
							int sys = 0;
							if( start_task != NULL )
							{
								signal( SIGCHLD, SIG_IGN );

								sys = system( start_task );
								debugp( DEBUGP_TCP, 7, "system(%s) = %d\n", start_task, sys );
							}
							fflush(stderr);
							exit(sys);
						}
						else
						{
							debugp( DEBUGP_TCP, 7, "PID %d spawned child %d to exec start_task\n", getpid(), f );

							debugp( DEBUGP_TCP, 0, "Starting audio management thread for session %08x\n", session->id );
							start_audio_mgmt_thread(session);
	
//							pthread_mutex_lock( session->ht_ready_mutex );
//							pthread_create( session->hairthread, NULL, hairtunes_thread, (void*)session );
//							we_are_streaming = 1;
//
//							// Wait for thread to become ready
//					
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
//							pthread_mutex_unlock( session->cc_mutex );
//							debugp( DEBUGP_TCP, 7, "Waiting for hairtunes thread to become ready\n" );
//							pthread_cond_wait( session->ht_ready, session->ht_ready_mutex );
//							pthread_mutex_unlock( session->ht_ready_mutex );
//							pthread_mutex_lock( session->cc_mutex );
						}
					}
					else if( strncmp( parsed->method, "FLUSH", 5 ) == 0 ) // Setup and start streaming
					{
						flush_request( session );
						//session->flush = 1;

						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
//						// Signal to the thread that something's changed
//						debugp( DEBUGP_TCP, 7, "control.h unlock cc_mutex\n" );
//						pthread_mutex_unlock( session->cc_mutex );
//						debugp( DEBUGP_TCP, 7, "control.h lock cc_param_changed_mutex\n" );
//						pthread_mutex_lock( session->cc_param_changed_mutex );
//						debugp( DEBUGP_TCP, 7, "control.h cond_signal cc_param_changed\n" );
//						pthread_cond_signal( session->cc_param_changed );
//						debugp( DEBUGP_TCP, 7, "control.h unlock cc_param_changed_mutex\n" );
//						pthread_mutex_unlock( session->cc_param_changed_mutex );
//						debugp( DEBUGP_TCP, 7, "control.h lock cc_mutex\n" );
//						pthread_mutex_lock( session->cc_mutex );
					}
					else if( strncmp( parsed->method, "TEARDOWN", 8 ) == 0 ) // Setup and start streaming
					{


						//session->teardown = 1;

						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						//// Signal to the thread that something's changed
						//debugp( DEBUGP_TCP, 7, "control.h unlock cc_mutex\n" );
						//pthread_mutex_unlock( session->cc_mutex );
						//debugp( DEBUGP_TCP, 7, "control.h lock cc_param_changed_mutex\n" );
						//pthread_mutex_lock( session->cc_param_changed_mutex );
						//debugp( DEBUGP_TCP, 7, "control.h cond_signal cc_param_changed\n" );
						//pthread_cond_signal( session->cc_param_changed );
						//debugp( DEBUGP_TCP, 7, "control.h unlock cc_param_changed_mutex\n" );
						//pthread_mutex_unlock( session->cc_param_changed_mutex );
						//debugp( DEBUGP_TCP, 7, "control.h lock cc_mutex\n" );
						//
						//debugp( DEBUGP_TCP, 3, "TEARDOWN request received, waiting for hairtunes thread to close\n" );
						//pthread_join( *(session->hairthread), NULL );

						// We are done streaming
						we_are_streaming = 0;
						
						// End task
						int f = fork();
						if( f == 0 )
						{
							int sys = 0;
							if( end_task != NULL )
							{
								signal( SIGCHLD, SIG_IGN );

								sys = system( end_task );
								debugp( DEBUGP_TCP, 7, "system(%s) = %d\n", end_task, sys );
							}
							fflush(stderr);
							exit(sys);
						}
						else
						{
							debugp( DEBUGP_TCP, 7, "PID %d spawned child %d to exec end_task\n", getpid(), f );
						}
						connection_close = 1;
						
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						//pthread_mutex_lock( session->cc_mutex );
					}
					else
					{
						debugp( DEBUGP_TCP, 1, "FIXME: Unhandled method: %s\n", parsed->method );
					}

					/**
					 * Apple-Challenge/Response
					 */
					char *apple_challenge = NULL;
					char *apple_response = NULL;
					apple_challenge = get_value_by_field_name( parsed, "Apple-Challenge" );
					if( apple_challenge != NULL ) // If there is an apple challenge, respond
					{
						apple_response = apple_respond( apple_challenge, ipbin, ipbinlen );
						tcp_message_add_header(response, mkheader("Apple-Response", apple_response));
					}

					/**
					 * Audio-Jack Status
					 */
					char audio_jack[64];
					sprintf( audio_jack, "%s; type=%s", audio_jack_status, audio_jack_type );
					tcp_message_add_header(response, mkheader("Audio-Jack-Status",audio_jack));

					/** 
					 * Connection: close
					 */
					if( connection_close )
					{
						tcp_message_add_header(response, mkheader("Connection", "close"));
					}

					/** 
					 * Send tcp message 
					 */
					//print_tcp_message(response);
					send_tcp_message(response,package->fd);

					/**
					 * Freebies
					 */
					free_tcp_message(response);
					free(apple_response);
					free(cseq_str);
				
					if(session)
					{
						debugp( DEBUGP_TCP, 7, "control.h session %08X unlock cc_mutex\n", session->id );
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						// XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX 
						//pthread_mutex_unlock( session->cc_mutex );
					}

					free_tcp_message(parsed);
					parsed = NULL;
					
					if(connection_close)
						break;
				}
			}
		}
	}
	close( package->fd );
	pthread_exit(NULL);
}
char *mallostrcpy( char *string )
{
	char *out = malloc( sizeof(char) * (strlen(string)+1) );
	strcpy(out,string);
	return out;
}

char *apple_respond( char *apple_challenge, unsigned char *ipbin, int ipbinlen )
{
	debugp( DEBUGP_TCP, 7, "Apple-Challenge is `%s'\n", apple_challenge );

	char *padded = malloc(sizeof(char) * (strlen(apple_challenge) + 4));
	strcpy(padded,apple_challenge);
	strcat(padded,"==\n");

	unsigned char *apple_challenge_decoded = unbase64( (unsigned char*)padded, strlen(padded));
	free(padded);

	apple_challenge_decoded = realloc(
			apple_challenge_decoded,
			sizeof(unsigned char) * 0x20 );
	unsigned char *acd = apple_challenge_decoded + 16;

	memcpy( acd, ipbin, ipbinlen );
	acd += ipbinlen;

	unsigned char md5sum[16];
	unsigned char *md5 = md5sum;
	if( MD5( (const unsigned char*)apname, strlen(apname), md5sum ) == NULL )
		return NULL;
	for( int i=0; i<6; i++ )
	{
		debugp( DEBUGP_TCP, 0, "%02X", *md5 );
		*acd++ = *md5++;
	}


	int pad = 0x20 - (acd-apple_challenge_decoded);
	while( pad-- )
		*acd++ = '\0';

	unsigned char *sig = malloc(RSA_size(private_key));
	memset(sig,0,RSA_size(private_key));
	int enc = RSA_private_encrypt( 0x20, apple_challenge_decoded, sig, private_key, RSA_PKCS1_PADDING );
	free(apple_challenge_decoded);

	char *apple_response = base64( sig, enc );
	free(sig);
	apple_response[strlen(apple_response)-1] = '\0';

	return apple_response;
}
unsigned char *unbase64( unsigned char *input, int length)
{
	BIO *b64, *bmem;

	unsigned char *buffer = malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}
char *base64(const unsigned char *input, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_set_flags(b64,BIO_FLAGS_BASE64_NO_NL);
	BIO_write(b64, input, length);
	(void)BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length);
	memcpy(buff, bptr->data, bptr->length-1);
	buff[bptr->length-1] = 0;

	BIO_free_all(b64);

	return buff;
}
void load_private_key( char *filename )
{
	FILE *fp;
	fp = fopen( filename, "r" );
	PEM_read_RSAPrivateKey( fp, &private_key, NULL, NULL );
	fclose(fp);
	return;
}
struct body_data *parse_body_keys( char *body )
{
	if(body==NULL)
		return NULL;

	struct body_data *data = malloc(sizeof(struct body_data));
	data->count = 0;
	data->keypairs = NULL;
	
	char *bp = body;
	while( (*bp == '\r') || (*bp == '\n') )
		bp++;


	char *key = body;
	char *value = NULL;
	while( *bp != '\0' )
	{
		if( *bp == '=' )
		{
			*bp = '\0';
			value = bp+1;
		}
		if( *bp == ':' )
		{
			key += 2;
			*bp = '\0';
			value = bp+1;
		}
		if( *bp == '\r' )
		{
			*bp++ = '\0';
			if(*bp=='\n')
				bp++;

			(data->count)++;
			data->keypairs = realloc( data->keypairs, sizeof(struct body_keypair) * data->count );
			data->keypairs[data->count-1].key = key;
			data->keypairs[data->count-1].value = value;

			key = bp;

			if((*bp=='\r')||(*bp=='\n'))
			{
				bp++;
				break;
			}
		}
		bp++;
	}

	return data;
}
void load_fmtp_into_session( char *fmtp_str, session_t *sess )
{
	// Parse fmtp tokens
	int fmtp[32];
	memset( fmtp, 0, sizeof(fmtp) );
	
	int *i = fmtp;
	char *arg;
	char *fmtp_buffer = malloc( sizeof(char) * (strlen(fmtp_str)+1) );
	strcpy( fmtp_buffer, fmtp_str );
	while( ( arg = strsep( &fmtp_buffer, " \t" ) ) )
	{
		*i++ = atoi(arg);
	}
	free(fmtp_buffer);

	sess->sample_rate = fmtp[11];
	sess->frame_size = fmtp[1];
	sess->sample_size = fmtp[3];

	if( sess->sample_size != 16 )
	{
		debugp( DEBUGP_TCP, 0, "Only 16-bit samples are supported!\n" );
		exit(-1);
	}

	sess->alac_setinfo_7a = fmtp[2];
	sess->alac_setinfo_rice_historymult = fmtp[4];
	sess->alac_setinfo_rice_initialhistory = fmtp[5];
	sess->alac_setinfo_rice_kmodifier = fmtp[6];
	sess->alac_setinfo_7f = fmtp[7];
	sess->alac_setinfo_80 = fmtp[8];
	sess->alac_setinfo_82 = fmtp[9];
	sess->alac_setinfo_86 = fmtp[10];
	sess->alac_setinfo_8a_rate = fmtp[11];

	return;
}
void load_rsaaeskey_into_session( char *key, session_t *sess )
{
	debugp( DEBUGP_TCP, 7, "base64 encoded rsaaeskey: %s\n", key );

	// unbase 64
	unsigned char b64rsaaeskey[strlen(key)+4];
	strcpy((char*)b64rsaaeskey,key);
	strcat((char*)b64rsaaeskey,"==");
	unsigned char *aeskey_enc = unbase64( b64rsaaeskey, strlen((char*)b64rsaaeskey) );

	// decrypt
	unsigned char aeskey_dec[16];
	int decrypted;
	if( ( decrypted = RSA_private_decrypt( 
					256, aeskey_enc, aeskey_dec, private_key, RSA_PKCS1_OAEP_PADDING ) ) < 0 )
	{
		unsigned long err = ERR_get_error();
		char ebuf[1024];
		ERR_error_string( err, ebuf );
		debugp( DEBUGP_TCP, 0, "Error in RSA_private_decrypt: %s\n", ebuf );
		exit(-1);
	}

	debugp( DEBUGP_TCP, 7, "Decrypted %d bytes\n", decrypted );

	AES_set_decrypt_key( aeskey_dec, 128, &sess->aeskey );

	free(aeskey_enc);

	return;
}
void load_aesiv_into_session( char *ivstring, session_t *sess )
{
	debugp( DEBUGP_TCP, 7, "base64 encoded aesiv: %s\n", ivstring );

	// unbase64
	unsigned char b64aesiv[strlen(ivstring)+4];
	strcpy((char*)b64aesiv,ivstring);
	strcat((char*)b64aesiv,"==\n");
	unsigned char *aesiv = unbase64( b64aesiv, strlen((char*)b64aesiv) );

	// copy to session struct
	memcpy(sess->aesiv,aesiv,16);
	free(aesiv);
	return;
}
void load_announce_params_into_session( struct body_data *data, session_t *sess )
{
	for( int k=0; k < data->count; k++ )
	{
		char *key = data->keypairs[k].key;
		char *value = data->keypairs[k].value;
	
		debugp( DEBUGP_TCP, 8, "key: %s value: %s\n", 
				data->keypairs[k].key,
				data->keypairs[k].value
			  );
	
		if( !strcmp( "fmtp", key ) )
		{
			load_fmtp_into_session( value, sess );
		}
		else if( !strcmp( "rsaaeskey", key ) )
		{
			load_rsaaeskey_into_session( value, sess );
		}
		else if ( !strcmp( "aesiv", key ) ) 
		{
			load_aesiv_into_session( value, sess );
		}
	}
	return;
}
void free_body_data( struct body_data *data )
{
	if(data==NULL)
		return;
	free(data->keypairs);
	free(data);
	return;
}

#endif
