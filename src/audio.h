#ifndef _AUDIO_H_
#define _AUDIO_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <pthread.h>
#include "debugp.h"

#include "constants.h"
#include "session.h"
#include "alac.h"
#include "fairport.h"
#include "masteraudio.h"


// 4 bytes
typedef struct {
	uint8_t a;
	uint8_t b;
	uint16_t seqnum;
} rtp_header_t;

// Time
// The timestamps used by iTunes and the device seems to come from a monotonic clock which 
// starts at 0 when they just started/booted. This monotonic clock's origin of time is the 
// unix epoch, which corresponds to 0x83aa7e80 seconds in NTP time.

// 8 bytes
typedef struct {
	/* Seconds since 1900-01-01 00:00:00 */
	uint32_t integer;

	/* Fraction of second (0..2^32) */
	uint32_t fraction;
} ntp_time_t;

// RTP Timestamp

// This is a 32 bit network order value increasing by 1 for each frame of data transmitted, 
// which means it increases by FRAMES_PER_PACKET for every RTP packet sent.

// TimingPacket - 32 bytes
typedef struct {
	rtp_header_t	header;
	uint32_t 		zero_padding;
	ntp_time_t		reference_time;
	ntp_time_t		received_time;
	ntp_time_t		send_time;
} timing_packet_t;

// SyncPacket - 20 bytes
typedef struct {
	rtp_header_t	header; // 4
	uint32_t			rtp_now; // 4
	ntp_time_t		time_now; // 8
	uint32_t			rtp_next; // 4
} sync_packet_t;

// ResendPacket - 8 bytes
typedef struct {
	rtp_header_t	header;
	uint16_t 		missed_seqnum;
	uint16_t 		count;
} resend_packet_t;

int init_udp_listeners(void);
void *udp_listener_func( void *arg );
int start_audio_mgmt_thread( session_t *sess );

// Callback functions for udp data
void audio_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host );
void control_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host );
void timing_data_callback( char *packet, ssize_t length, struct sockaddr_storage *host );

int flush_request( session_t *sess );
int set_volume( session_t *sess, double vol );

// Helpers
uint8_t get_source( rtp_header_t *header );
uint8_t get_payload_type( rtp_header_t *header );
int get_marker( rtp_header_t *header );
int get_extension( rtp_header_t *header );

#endif
