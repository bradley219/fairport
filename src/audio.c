#ifndef _AUDIO_SRC_
#define _AUDIO_SRC_

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>
#include <sys/stat.h>
#include <time.h>

#include "audio.h"


static int audio_sock;
static int control_sock;
static int timing_sock;

static pthread_t udp_audio_thread = 0;
static pthread_t udp_control_thread = 0;
static pthread_t udp_timing_thread = 0;

// Data struct for udp listeners
typedef struct {
	int socket;
	unsigned port;
	void (*callback)(char*,ssize_t,struct sockaddr_storage *);
} udp_listener_data_t;

static udp_listener_data_t audio_thread_data;
static udp_listener_data_t control_thread_data;
static udp_listener_data_t timing_thread_data;


int init_udp_listeners(void)
{
	int retval = 0;
	if( udp_audio_thread != 0 )
		return 0;

	struct sockaddr_in si;
	int type = AF_INET;
	struct sockaddr* si_p = (struct sockaddr*)&si;
	socklen_t si_len = sizeof(si);

	unsigned short *sin_port = &si.sin_port;
	memset( &si, 0, sizeof(si) );

	si.sin_family = type;

#ifdef SIN_LEN
	si.sin_len = sizeof(si);
#endif

	si.sin_addr.s_addr = htonl(INADDR_ANY);

	// Create sockets
	if( ( audio_sock = socket( type, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error creating audio socket; socket() returned %d\n", audio_sock );
		retval = -1;
	}
	if( ( control_sock = socket( type, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error creating control socket; socket() returned %d\n", control_sock );
		retval = -1;
	}
	if( ( timing_sock  = socket( type, SOCK_DGRAM, IPPROTO_UDP ) ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error creating timing socket; socket() returned %d\n", timing_sock );
		retval = -1;
	}

	// Bind sockets to ports 6000,6001,6002
	unsigned port;
	port = 6000;
	*sin_port = htons(port);
	if( bind( audio_sock, si_p, si_len ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error binding to audio UDP port %u\n", port );
		retval = -1;
	}
	port = 6001;
	*sin_port = htons(port);
	if( bind( control_sock, si_p, si_len ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error binding to control UDP port %u\n", port );
		retval = -1;
	}
	port = 6002;
	*sin_port = htons(port);
	if( bind( timing_sock, si_p, si_len ) < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error binding to timing UDP port %u\n", port );
		retval = -1;
	}

	// Fill thread data structs with sockets
	audio_thread_data.socket = audio_sock;
	control_thread_data.socket = control_sock;
	timing_thread_data.socket = timing_sock;
	
	// Fill thread data structs with port numbers for reference
	audio_thread_data.port = 6000;
	control_thread_data.port = 6001;
	timing_thread_data.port = 6002;
	
	// Fill thread data structs with callback functions
	audio_thread_data.callback = &audio_data_callback;
	control_thread_data.callback = &control_data_callback;
	timing_thread_data.callback = &timing_data_callback;

	// Create threads
	pthread_create( &udp_audio_thread, NULL, udp_listener_func, (void*)&audio_thread_data );
	pthread_create( &udp_control_thread, NULL, udp_listener_func, (void*)&control_thread_data );
	pthread_create( &udp_timing_thread, NULL, udp_listener_func, (void*)&timing_thread_data );

	return retval;
}
void *udp_listener_func( void *arg )
{
	udp_listener_data_t *data = (udp_listener_data_t*)arg;

	struct sockaddr_storage remote_host;
	socklen_t si_len = sizeof(struct sockaddr_in);
	char packet[MAX_PACKET];
	
	char remote_address[INET6_ADDRSTRLEN];

	while(1)
	{
		fd_set set;
		FD_ZERO(&set);
		FD_SET(data->socket, &set);
		
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
		int ready = select( data->socket + 1, &set, NULL, NULL, &timeout );
		if( ready < 0 )
		{
			debugp( DEBUGP_DEFAULT, 0, "udp_listener_func: UDP port %u: select() returned %d\n", data->port, ready );
			kill( getpid(), SIGINT );
		}
		else if( FD_ISSET(data->socket,&set) )
		{
			ssize_t rlen = recvfrom( data->socket, packet, sizeof(packet), 0, (struct sockaddr*)&remote_host, &si_len );

			assert( rlen <= MAX_PACKET );

			// Get string value of remote host
			inet_ntop( AF_INET, (void*)&(((struct sockaddr_in*)&remote_host)->sin_addr), remote_address, sizeof(remote_address) );
			debugp( DEBUGP_DEFAULT, 8, "Received %d bytes from %s UDP port %u\n", rlen, remote_address, data->port );

			// Call the callback function with data
			data->callback( packet, rlen, &remote_host );
		}
		else
		{
			debugp( DEBUGP_DEFAULT, 8, "udp_listener_func: UDP port %u: select() timed out\n", data->port );
		}
	}

	pthread_exit(NULL);
}
int copy_packet_and_signal_thread( session_t *sess, void*packet_buffer, size_t length, int type )
{
	int retval = 0;

	// Copy to session data
	pthread_mutex_lock( &sess->mutex );	
	memcpy( sess->audio_packet_buffer, packet_buffer, length );
	sess->audio_packet_buffer_len = length;
	sess->packet_buffer_updated = type; 
	
	// Release the mutex to the management thread
	pthread_mutex_unlock( &sess->mutex );	

	// Signal thread
	pthread_mutex_lock( &sess->packet_sig_mutex );
	pthread_cond_signal( &sess->packet_sig_cond );
	pthread_mutex_unlock( &sess->packet_sig_mutex );

	return retval;
}
void audio_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host )
{

	assert(length>=12);

	// First 4 bytes are an rtp_header
	rtp_header_t *header = (rtp_header_t*)packet;

	// Next 4 bytes are to be ignored?? TODO but they sure seem like something.
//	for( int i=0; i < 30; i++ )
//		debugp( DEBUGP_AUDIO_PACKETS, 4, "[%02X] . ", (uint8_t)packet[i] );
//
//	debugp( DEBUGP_AUDIO_PACKETS, 4, "\n" );

	uint32_t signature = ntohl( *((uint32_t*)(packet+8)) );

	assert( get_payload_type(header) == PAYLOAD_TYPE_AUDIO );

	// Find the session that this packet belongs to
	session_t *sess = find_session_by_audio_signature( signature );

	if(sess)
	{
		debugp( DEBUGP_AUDIO_PACKETS, 8, "  session: %08x\n", sess->id );

		debugp( DEBUGP_AUDIO_PACKETS, 8, "  signature: %08x\n", signature );
		debugp( DEBUGP_AUDIO_PACKETS, 8, "  sequence: %04x\n", ntohs(header->seqnum) );
		//debugp( DEBUGP_AUDIO_PACKETS, 8, "  payload type: %02x\n", get_payload_type( header ) );
		//debugp( DEBUGP_AUDIO_PACKETS, 8, "  source: %02x\n", get_source( header ) );
		//debugp( DEBUGP_AUDIO_PACKETS, 8, "  extension: %d\n", get_extension( header ) );
		//debugp( DEBUGP_AUDIO_PACKETS, 8, "  marker: %d\n", get_marker( header ) );

		copy_packet_and_signal_thread( sess, packet, length, 1 );
	}
	else
	{
		debugp( DEBUGP_AUDIO_PACKETS, 8, "No session found for audio signature %08x\n", signature );
	}

	return;
}
void control_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host )
{
	//debugp( DEBUGP_CONTROL_PACKETS, 4, "control_data_callback: hello!\n" );

	//int max = (length > 30) ? 30 : length;
	//for( int i=0; i < max; i++ )
	//	debugp( DEBUGP_CONTROL_PACKETS, 4, "[%02X] . ", (uint8_t)packet[i] );
	//debugp( DEBUGP_CONTROL_PACKETS, 4, "\n" );
	
	// First 4 bytes are an rtp_header
	rtp_header_t *header = (rtp_header_t*)packet;

	uint8_t payload_type = get_payload_type( header );
	
	if( payload_type == PAYLOAD_TYPE_RESENT_AUDIO ) // This is re-sent audio data
	{

		packet += 4;
		length -= 4;

		header = (rtp_header_t*)packet;

		uint32_t signature = ntohl( *((uint32_t*)(packet+8)) );

		session_t *sess = find_session_by_control_signature( signature );

		if( sess )
		{
			copy_packet_and_signal_thread( sess, packet, length, 2 );
		}
	}
	else if( (payload_type == PAYLOAD_TYPE_SYNC) && (length==20) )
	{
		debugp( DEBUGP_CONTROL_PACKETS, 4, "SYNC packet received\n" );
		
		for( int i=0; i < 20; i++ )
			debugp( DEBUGP_CONTROL_PACKETS, 4, "[%02X].", (uint8_t)packet[i] );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "\n" );

		sync_packet_t *sync = (sync_packet_t*)packet;

		sync->rtp_now = ntohl( sync->rtp_now );
		sync->rtp_next = ntohl( sync->rtp_next );
		sync->time_now.integer = ntohl( sync->time_now.integer );
		sync->time_now.fraction = ntohl( sync->time_now.fraction );

		//debugp( DEBUGP_CONTROL_PACKETS, 4, "  extension:          %10d\n", get_extension( header ) );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "  rtpnow:            %10lu\n", sync->rtp_now );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "  rtp next packet:   %10lu\n", sync->rtp_next );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "  latency:           %10lu (%f sec)\n", sync->rtp_next - sync->rtp_now, (double)(sync->rtp_next-sync->rtp_now) / (double)44100  );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "  time_now.integer:  %10lu\n", sync->time_now.integer );
		debugp( DEBUGP_CONTROL_PACKETS, 4, "  time_now.fraction: %10lu\n", sync->time_now.fraction );

	}
	else
	{
		debugp( DEBUGP_CONTROL_PACKETS, 4, "Packet is something else!\n" );
	}
	return;
}
void timing_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host )
{
	debugp( DEBUGP_TIMING_PACKETS, 4, "\n\n\n*************timing_data_callback: hello!*************\n\n\n" );
	debugp( DEBUGP_TIMING_PACKETS, 4, "Searching for session by host..\n" );
	
	session_t *sess = find_session_by_host( host );

	if( sess )
	{
		copy_packet_and_signal_thread( sess, packet, length, 2 );
	}
	else
	{
		debugp( DEBUGP_TIMING_PACKETS, 4, "No session found for host\n" );
	}
			


	return;
}

int request_timing( struct sockaddr_storage *host )
{
	int retval = 0;
	int type = AF_INET;

	struct sockaddr_in si;
	memcpy( &si, host, sizeof(struct sockaddr_in) );
	struct sockaddr* si_p = (struct sockaddr*)&si;

	si.sin_port = htons(6002); // timing port
	si.sin_family = type;

	int sock = timing_sock;

	timing_packet_t packet;

	packet.header.a = RTP_HEADER_B_MARKER;
	packet.header.b = RTP_HEADER_B_MARKER | PAYLOAD_TYPE_TIMING_REQUEST;

	packet.header.seqnum = htons(0x07);
	packet.zero_padding = 0;

	packet.reference_time.integer = 0;
	packet.reference_time.fraction = 0;
	packet.received_time.integer = 0;
	packet.received_time.fraction = 0;

	// get time
	struct timespec now;

	clock_gettime( CLOCK_REALTIME, &now );
	
	packet.send_time.integer  = htonl( now.tv_sec + 875912342 );
	packet.send_time.fraction = htonl( now.tv_nsec );

	debugp( DEBUGP_TIMING_PACKETS, 4, "Sending time request packet\n" );
	debugp( DEBUGP_TIMING_PACKETS, 4, "  Time.integer:  %10lu\n", now.tv_sec );
	debugp( DEBUGP_TIMING_PACKETS, 4, "  Time.fraction: %10lu\n", now.tv_nsec );

	unsigned char *c = (unsigned char*)&packet;
	for( int i=0; i < sizeof(packet); i++ )
	{
		debugp( DEBUGP_TIMING_PACKETS, 4, "[%02x] . ", *c++ );
	}
	debugp( DEBUGP_TIMING_PACKETS, 4, "\n" );

	ssize_t sent = sendto( sock, &packet, sizeof(packet), 0, si_p, sizeof(struct sockaddr_in) );

	retval = sent;

	assert(sent==32);

	return retval;
}

int request_resend( uint16_t seqnum, uint16_t count, struct sockaddr_storage *host )
{
	int retval = 0;
	int type = AF_INET;

	struct sockaddr_in si;
	memcpy( &si, host, sizeof(struct sockaddr_in) );
	struct sockaddr* si_p = (struct sockaddr*)&si;

	si.sin_port = htons(6001); // control port
	si.sin_family = type;

	int sock = control_sock;
	
	resend_packet_t packet;

	// XXX this is corrent, but seems wrong (thanks, apple)
	packet.header.a = RTP_HEADER_B_MARKER;
	packet.header.b = RTP_HEADER_B_MARKER | PAYLOAD_TYPE_RANGE_RESEND;

	packet.header.seqnum = htons(seqnum + count);
	
	packet.missed_seqnum = htons(seqnum);
	packet.count = htons(count);

	ssize_t sent = sendto( sock, &packet, sizeof(packet), 0, si_p, sizeof(struct sockaddr_in) );

	retval = sent;

	assert(sent==8);

	return retval;
}
int init_decoder( session_t *sess )
{
	int retval = 0;

	sess->decoder_info = create_alac( sess->sample_size, sess->num_channels );
	
	sess->decoder_info->setinfo_max_samples_per_frame = sess->frame_size;
	sess->decoder_info->setinfo_7a = sess->alac_setinfo_7a;
	sess->decoder_info->setinfo_sample_size = sess->sample_size;
	sess->decoder_info->setinfo_rice_historymult = sess->alac_setinfo_rice_historymult;
	sess->decoder_info->setinfo_rice_initialhistory = sess->alac_setinfo_rice_initialhistory;
	sess->decoder_info->setinfo_rice_kmodifier = sess->alac_setinfo_rice_kmodifier;
	sess->decoder_info->setinfo_7f = sess->alac_setinfo_7f;
	sess->decoder_info->setinfo_80 = sess->alac_setinfo_80;
	sess->decoder_info->setinfo_82 = sess->alac_setinfo_82;
	sess->decoder_info->setinfo_86 = sess->alac_setinfo_86;
	sess->decoder_info->setinfo_8a_rate = sess->alac_setinfo_8a_rate;

	allocate_buffers(sess->decoder_info);

	return retval;
}

/**
 * Get index number within audio buffer from sequence number 
 */
uint16_t bufidx( uint16_t seqno, session_t *sess )
{
	uint16_t idx = seqno % sess->buffer_frames;
	return idx;
}

int seq_order( uint16_t a, uint16_t b )
{
	signed short d = a - b;
	return ( d > 0 );
}

/**
 * Sync this session's audio buffer (set all ready to 0)
 */
int ab_resync( session_t *sess )
{
	int retval = 0;

	for( int i = 0; i < sess->buffer_frames; i++ )
	{
		sess->audio_buffer[i].ready = 0;
		memset( sess->audio_buffer[i].data, 0, 4 * ( sess->frame_size + 3 ) );
	}
	sess->ab_synced = 0;
	sess->ab_buffering = 1;
	return retval;
}

int buffer_fake( abuf_t *buffer, abuf_t *before, abuf_t *after, session_t *sess )
{
	int retval = 0;

	if( buffer->ready <= 0 )
	{
		if( (before->ready == 0) && (after->ready == 0) )
		{
			signed short start_left = before->data[(sess->frame_size/2)-2];
			signed short start_right = before->data[(sess->frame_size/2)-1];
			signed short end_left = after->data[0];
			signed short end_right = after->data[1];

			double left_slope = (end_left-start_left) / (sess->frame_size/2);
			double right_slope = (end_right-start_right) / (sess->frame_size/2);

			signed short *buf = buffer->data;
			for( int i = 0; i < (sess->buffer_frames / 2); i++ )
			{
				// Left
				*buf++ = (double)i * left_slope + (double)start_left;
			
				// Right
				*buf++ = (double)i * right_slope + (double)start_right;

			}

		}
		else
			retval = 2;
	}
	else
		retval = 1;

	return retval;
}

static inline short dithered_vol( short sample, session_t *sess ) 
{
    short rand_a, rand_b;
    long out;

    rand_a = rand() & 0xffff;
    rand_b = rand() & 0xffff;

    out = (long)sample * sess->fix_volume;

	 if( sess->fix_volume < 0x1000 )
	 {
		 out += rand_a;
		 out -= rand_b;
	 }

	 out >>= 16;
    
	 return out;
}

int ab_flushout( session_t *sess, uint16_t frames )
{
	int retval = 0;

	abuf_t *buffer = sess->audio_buffer + sess->read_idx;
	uint16_t idx = sess->read_idx;

	// Prepare an output buffer
	char *output_buffer = malloc( sizeof(char) * (sess->frame_size * sess->num_channels * sizeof(signed short) * frames) );
	memset( output_buffer, 0, sizeof(char) * (sess->frame_size * sess->num_channels * sizeof(signed short) * frames) );
	char *ob = output_buffer;

	uint16_t f = frames;
	abuf_t *last_buffer;
	while( f-- )
	{
		if( (*buffer).ready <= 0 )
		{
			if( ((f+1) != frames) && (f!=0) )
			{
				abuf_t *next_buffer = buffer + 1;
				if( next_buffer >= (sess->audio_buffer + sess->buffer_frames) )
					next_buffer = sess->audio_buffer;

				int r = buffer_fake( buffer, last_buffer, next_buffer, sess );
				debugp( DEBUGP_AUDIO_OUTPUT, 3, "Faked a buffer at index %d; result = %d\n", idx, r );
			}
			else
			{
				debugp( DEBUGP_AUDIO_OUTPUT, 3, "Error, unable to repair buffer at index %d\n", idx );
			}
		}

		short *dataptr = (*buffer).data;
		for( int i = 0; i < sess->frame_size * 2; i++ )
		{
			short data = *dataptr;
			*dataptr = dithered_vol( data, sess );
			dataptr++;
		}

		memcpy( ob, (*buffer).data, sess->frame_size * sess->num_channels * sizeof(signed short) );

		ob += sess->frame_size * sess->num_channels * sizeof(signed short);


		(*buffer).ready = 0;

		last_buffer = buffer;
		
		buffer++;
		idx++;
		
		if( (buffer - sess->audio_buffer) >= sess->buffer_frames )
		{
			buffer = sess->audio_buffer;
			idx = 0;
		}
	}

	sess->master_buffer_ptr = write_to_master_buffer( output_buffer, frames * sess->frame_size, sess->master_buffer_ptr );
	
	free(output_buffer);

	return retval;
}

int alac_decode( session_t *sess, short *dest, char *src, int len )
{
	int retval = 0;
	unsigned char packet[MAX_PACKET];
	assert( len <= MAX_PACKET );

	unsigned char iv[16];

	memcpy( iv, sess->aesiv, sizeof(iv) );
	int i;
	for( i=0; (i+16) <= len; i += 16 )
	{
		AES_cbc_encrypt( (unsigned char*)src+i, packet+i, 0x10, &sess->aeskey, iv, AES_DECRYPT );
	}
	if( len & 0xf )
	{
		memcpy( packet+i, src+i, len & 0xf );
	}

	int outsize;

	decode_frame( sess->decoder_info, packet, dest, &outsize );

	//debugp( DEBUGP_AUDIO_OUTPUT, 4, "outsize=%d; sess->frame_size = %d\n", outsize, sess->frame_size );
	assert( outsize == ( 4 * sess->frame_size ) );
	
	return retval;
}
int buffer_put_packet( abuf_t *buffer, char *packet, int len, session_t *sess )
{
	int retval = 0;
	alac_decode( sess, buffer->data, packet, len );
	buffer->ready = 1;
	return retval;
}

/**
 * Allocate this session's audio buffer
 */
int init_audio_buffer( session_t *sess )
{
	int retval = 0;

	sess->audio_buffer = malloc( sizeof(abuf_t) * sess->buffer_frames );
	memset( sess->audio_buffer, 0, sizeof(abuf_t) * sess->buffer_frames );

	for( int i = 0; i < sess->buffer_frames; i++ )
	{
		sess->audio_buffer[i].data = malloc( 4 * ( sess->frame_size + 3 ) );
	}

	ab_resync(sess);

	return retval;
}

/**
 * Audio management thread
 */
void *audio_mgmt_thread_func( void *arg )
{
	session_t *session = (session_t*)arg;

	// Setup
	pthread_mutex_lock( &session->mutex );
	
	session->packet_buffer_updated = 0;
	session->master_buffer_ptr = NULL;

	init_decoder(session);
	init_audio_buffer(session);

	request_timing( &session->remote_host );
	request_timing( &session->remote_host );
	request_timing( &session->remote_host );

	int till_flushout = session->buffer_frames;
	int first = 1;
	session->seqnum = 0;
	session->read_seqnum = 0;
	session->read_idx = 0;

	
	pthread_mutex_unlock( &session->mutex );

	int till_timing_request = 1000;
	while(1)
	{
		pthread_mutex_lock( &session->packet_sig_mutex );
		pthread_cond_wait( &session->packet_sig_cond, &session->packet_sig_mutex );
	
		//struct timespec waittime = { .tv_sec = 1, .tv_nsec = 0 };
		//pthread_cond_timedwait( &session->packet_sig_cond, &session->packet_sig_mutex, &waittime );

		pthread_mutex_lock( &session->mutex );

		if( --till_timing_request == 0 )
		{
			request_timing( &session->remote_host );
			till_timing_request = 1000;
		}

		if( session->packet_buffer_updated ) // will be 2 if the packet is a requested resend
		{
			// Decode the packet header
			rtp_header_t *header = (rtp_header_t*)&session->audio_packet_buffer;
			uint16_t seq = ntohs(header->seqnum);

			// get payload_type
			uint8_t payload_type = get_payload_type(header);

			if( payload_type == PAYLOAD_TYPE_AUDIO )
			{

				if(first)
				{
					first = 0;
					session->read_seqnum = seq;
					session->seqnum = seq;
					session->read_idx = bufidx( seq, session );
				}


				debugp( DEBUGP_AUDIO_MGMT, 7, "Audio mgmt thread for session %08x received audio packet seqnum %04x ", 
						session->id, 
						seq
						);
				
				uint16_t idx = bufidx( seq, session );
				abuf_t *buffer = session->audio_buffer + idx;

				if( session->packet_buffer_updated == 1 ) // normal audio packet
				{
					if( session->seqnum != seq ) // packet arrived out of sequence
					{
						debugp( DEBUGP_AUDIO_MGMT, 7, " == Packet arrived out of sequence ==\n" );

						if( seq > session->seqnum ) // we missed packets; need to keep track of them and request resends
						{
							uint16_t missed_seqnum = session->seqnum;
							uint16_t missed_count = 0;
							do {
								missed_count++;
								debugp( DEBUGP_AUDIO_MGMT, 4, "Requesting resend on seqnum %04x\n", session->seqnum );
								
								// Mark packet as missed
								session->audio_buffer[bufidx(session->seqnum,session)].ready = -1;

							} while( ++session->seqnum < seq);

							request_resend( missed_seqnum, missed_count, &session->remote_host );
						}
	//					else // TODO: anything?
	//					{
	//					}

						session->seqnum = seq;
					}
					else
					{
						debugp( DEBUGP_AUDIO_MGMT, 7, "\n" );
					}
					session->seqnum++;
				
					// Put packet into buffer
					buffer_put_packet( buffer, session->audio_packet_buffer+12, session->audio_packet_buffer_len-12, session );
					
					// Check for requested resends that we still haven't seen
					// Go back 30 packets
					uint16_t old_seqnum = seq - BUFFER_LEAD_FRAMES;
					for( int i=0; i < (BUFFER_LEAD_FRAMES/10); i++ )
					{
						int idx = bufidx( old_seqnum, session );
						if( session->audio_buffer[idx].ready == -1 )
						{
							debugp( DEBUGP_AUDIO_MGMT, 4, "Requesting resend on seqnum %04x\n", old_seqnum );
							request_resend( old_seqnum, 1, &session->remote_host );
						}
						old_seqnum += 10;
					}

				}
				else if( session->packet_buffer_updated == 2 ) // resent audio packet that we requested
				{
					if( seq > session->read_seqnum )
					{
						debugp( DEBUGP_AUDIO_MGMT, 4, "Received re-sent audio packet seqnum %04x\n", seq );
					
						// Put packet into buffer
						buffer_put_packet( buffer, session->audio_packet_buffer+12, session->audio_packet_buffer_len-12, session );
					}
				}

				if( --till_flushout == 0 )
				{
					// flush out the buffer
					ab_flushout( session, session->buffer_frames - session->buffer_lead_frames );
					
					// reset counters/pointers
					session->read_seqnum += session->buffer_frames - session->buffer_lead_frames;;
					session->read_idx = bufidx( session->read_seqnum, session );
					till_flushout = session->buffer_frames - session->buffer_lead_frames;
				}
				if( session->read_seqnum >= session->buffer_frames )
				{
					session->read_seqnum -= session->buffer_frames;
				}
				
#define PRINT_BUFFER
#ifdef PRINT_BUFFER
				// Print index within buffer
				int width = (session->buffer_frames < window_size.ws_col) ? session->buffer_frames : window_size.ws_col - 2;
				
				//width -= debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, "fr/pkt=%d [", session->frame_size );

				for( int i=0; i < width; i++ )
				{
					int x = i * session->buffer_frames / width;

					buffer = session->audio_buffer + x;

					if( buffer->ready == 0 )
						debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, " " );
					else if( buffer->ready == -1 )
						debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, "_" );
					else if( buffer->ready == 2 )
						debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, "X" );
					else 
						debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, "x" );
				}
				debugp( DEBUGP_AUDIO_BUFFER_PRINT, 3, "]\n" );
#endif

			}
			else if( payload_type == PAYLOAD_TYPE_TIMING_RESPONSE )
			{
				debugp( DEBUGP_AUDIO_MGMT, 4, "Audio management thread for session %08x received timing packet response\n", session->id );
			
				assert( session->audio_packet_buffer_len == 32 );
				timing_packet_t *tpacket = (timing_packet_t*)&session->audio_packet_buffer;

				ntp_time_t *reference_time = &tpacket->reference_time;
				ntp_time_t *received_time = &tpacket->received_time;
				ntp_time_t *send_time = &tpacket->send_time;

				time_t reference_time_sec = ntohl(reference_time->integer) - 875912342;
				time_t received_time_sec = ntohl(received_time->integer) - 875912342;
				time_t send_time_sec = ntohl(send_time->integer) - 875912342;

				char time_buffer[128];
				struct tm *ltime = NULL;

				ltime = localtime( &reference_time_sec );
				strftime( time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", ltime );
				debugp( DEBUGP_AUDIO_MGMT, 4, "Reference time:\n" );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   %s\n", time_buffer );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   integer:  %10u\n", reference_time_sec );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   fraction: %10u\n", ntohl(reference_time->fraction));

				ltime = localtime( &received_time_sec );
				strftime( time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", ltime );
				debugp( DEBUGP_AUDIO_MGMT, 4, "Received time:\n" );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   %s\n", time_buffer );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   integer:  %10u\n", received_time_sec );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   fraction: %10u\n", ntohl(received_time->fraction) );

				ltime = localtime( &send_time_sec );
				strftime( time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", ltime );
				debugp( DEBUGP_AUDIO_MGMT, 4, "Send time:\n" );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   %s\n", time_buffer );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   integer:  %10u\n", send_time_sec );
				debugp( DEBUGP_AUDIO_MGMT, 4, "   fraction: %10u\n", ntohl(send_time->fraction) );
				
				
				double fref = ((double)ntohl(reference_time->integer) - 875912342 + (double)ntohl(reference_time->fraction)/(double)1000000000);
				double fsend = ((double)ntohl(send_time->integer) - 875912342 + (double)ntohl(send_time->fraction)/(double)1000000000);
				double freceived = ((double)ntohl(received_time->integer) - 875912342 + (double)ntohl(received_time->fraction)/(double)1000000000);
				
				// get time
				struct timespec now;
				double fnow = 0;
				clock_gettime( CLOCK_REALTIME, &now );
				fnow = (double)(now.tv_sec) + (double)now.tv_nsec/(double)1000000000;

				double round_trip_delay = (fnow - fref) - (fsend - freceived);
				double offset = ((freceived - fref) + (fsend - fnow)) / 2.0;
				double leg1 = (freceived - fref);
				double leg2 = (fsend - fnow);

				debugp( DEBUGP_AUDIO_MGMT, 4, "Round trip delay: %f\n", round_trip_delay );
				debugp( DEBUGP_AUDIO_MGMT, 4, "Offset:           %f\n", offset );
				debugp( DEBUGP_AUDIO_MGMT, 4, "\n" );

			}
			
			// reset flag
			session->packet_buffer_updated = 0;
		}
		else if( session->flush_request )
		{
			debugp( DEBUGP_AUDIO_MGMT, 3, "**************************\nFLUSH!!!\n********************************\n" );
			
			session->flush_request = 0;
	
			till_flushout = session->buffer_frames;
			
			ab_resync(session);
		
			first = 1;
			session->master_buffer_ptr = NULL;
		}
		else
		{
			debugp( DEBUGP_AUDIO_MGMT, 4, "pthread_cond_timedwait() timed out??\n" );
		}
		
		pthread_mutex_unlock( &session->packet_sig_mutex );
	
		pthread_mutex_unlock( &session->mutex );
	}

	pthread_exit(NULL);
}
int start_audio_mgmt_thread( session_t *sess )
{
	int retval = 0;

	pthread_mutex_lock( &sess->mutex );

	if( sess->thread != 0 )
	{
		retval = -1;
	}
	else
	{
		pthread_create( &sess->thread, NULL, audio_mgmt_thread_func, (void*)sess );
		retval = 0;
	}

	pthread_mutex_unlock( &sess->mutex );
	return retval;
}
int flush_request( session_t *sess )
{
	int retval = 0;

	// Set flag
	pthread_mutex_lock( &sess->mutex );	
	sess->flush_request = 1;
	
	// Release the mutex to the management thread
	pthread_mutex_unlock( &sess->mutex );	

	// Signal thread
	pthread_mutex_lock( &sess->packet_sig_mutex );
	pthread_cond_signal( &sess->packet_sig_cond );
	pthread_mutex_unlock( &sess->packet_sig_mutex );

	return retval;
}
int set_volume( session_t *sess, double vol )
{
	int retval = 0;

	pthread_mutex_lock( &sess->mutex );	
	sess->volume = vol;
	sess->fix_volume = 65536.0 * pow( 10.0, 0.05 *vol );
	pthread_mutex_unlock( &sess->mutex );	

	return retval;
}

// Little helpers
uint8_t get_source( rtp_header_t *header )
{
	uint8_t source = header->a & RTP_HEADER_A_SOURCE;
	return source;
}
int get_extension( rtp_header_t *header )
{
	int extension = (header->a & RTP_HEADER_A_EXTENSION) ? 1 : 0;
	return extension;
}
int get_marker( rtp_header_t *header )
{
	int marker = (header->b & RTP_HEADER_B_MARKER) ? 1 : 0;
	return marker;
}
uint8_t get_payload_type( rtp_header_t *header )
{
	uint8_t ptype = header->b & RTP_HEADER_B_PAYLOAD_TYPE;
	return ptype;
}
#endif
