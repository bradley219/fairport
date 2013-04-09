#ifndef _FAIRPORT_SESSION_H_
#define _FAIRPORT_SESSION_H_

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <arpa/inet.h>
#include <ao/ao.h>

#include "../config.h"
#include "constants.h"
//#include "hairtunes.h"
#include "alac.h"

typedef struct {
	int ready;
	signed short *data;
} abuf_t;

typedef struct {

	// Session's mutex
	pthread_mutex_t mutex;	

	// Session's audio management thread
	pthread_t thread;

	uint32_t id;
	uint32_t audio_signature;
	uint32_t control_signature;

	// Host info
	struct sockaddr_storage remote_host;
	
	// Session expiration info
	struct timespec expire;

	// Encryption parameters
	unsigned char aesiv[16];
	AES_KEY aeskey;

	// ALAC audio parameters
	alac_file *decoder_info;
	int num_channels;
	int sample_rate;
	int frame_size; // frames per packet
	int sample_size;
	int alac_setinfo_7a;
	int alac_setinfo_rice_historymult;
	int alac_setinfo_rice_initialhistory;
	int alac_setinfo_rice_kmodifier;
	int alac_setinfo_7f;
	int alac_setinfo_80;
	int alac_setinfo_82;
	int alac_setinfo_86;
	int alac_setinfo_8a_rate;

	// Audio processing
	double bf_playback_rate;

	int buffer_frames;
	int buffer_lead_frames;
	int ab_synced;
	int ab_buffering;

	uint16_t read_seqnum;
	uint16_t read_idx;
	uint16_t write_idx;
	uint16_t seqnum;

	char *master_buffer_ptr;

	// Timing
	double ntp_offset;

	// Thread_signaling
	char audio_packet_buffer[MAX_PACKET];
	size_t audio_packet_buffer_len;
	pthread_mutex_t packet_sig_mutex;
	pthread_cond_t  packet_sig_cond;

	int packet_buffer_updated;
	int flush_request;

	abuf_t *audio_buffer;

	// Volume
	double volume; // as sent by iTunes
	long fix_volume; // converted
	
} session_t;

#include "audio.h"


int close_session( session_t *session );
session_t *create_session( int timeout );
session_t *find_session( uint32_t id );
session_t *find_session_by_str( char *session_id );
session_t *get_first_session(void);
session_t *find_session_by_audio_signature( uint32_t sig );
session_t *find_session_by_control_signature( uint32_t sig );
session_t *find_session_by_host( struct sockaddr_storage *search );


#endif
