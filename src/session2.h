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
#include "hairtunes.h"
#include "alac.h"

struct session {
	struct session *next;

	uint32_t id;
	struct timespec expire;

	// hairtunes vars

	alac_file *decoder_info;
	int ab_buffering;
	int ab_synced;
	int buffer_start_fill;
	int sampling_rate;
	abuf_t *audio_buffer;
	volatile seq_t ab_read;
	volatile seq_t ab_write;

	char *fmtp;
	unsigned char aeskey[16];
	unsigned char aesiv[16];
	AES_KEY aes;

	int frame_size;
	
	double bf_playback_rate;

	double volume;
	volatile long fix_volume;

	int   timing_port; //tport
	int   control_port; //cport
	int   server_port; //dport
	
	double bf_est_drift;
	biquad_t bf_drift_lpf;
	double bf_est_err;
	double bf_last_err;
	biquad_t bf_err_lpf;
	biquad_t bf_err_deriv_lpf;
	double desired_fill;
	int fill_count;

	// rtp sockets
	int   sock;
	int   tsock;
	int   csock;

	unsigned long ao_plays;
	
	int   flush;
	int   teardown;

	// pthread variables
	pthread_t *hairthread;

	pthread_mutex_t *cc_mutex;
	pthread_mutex_t *cc_param_changed_mutex;
	pthread_cond_t *cc_param_changed;
	pthread_mutex_t *ht_ready_mutex;
	pthread_cond_t *ht_ready;
	pthread_mutex_t *vol_mutex;
	pthread_mutex_t *ab_mutex;
	pthread_cond_t *ab_buffer_ready;

	struct sockaddr_storage *rtp_client;
};
int close_session( struct session *session );
struct session *create_session( int timeout );
struct session *find_session( char *session_id );
struct session *get_first_session(void);

/*
struct client_context {
	struct sockaddr_in peer;
	int  fd;
	int  ipbinlen;
	unsigned char *ipbin[6];
	int  cseq;
	char *client_instance;
	char *dacp_id;
	char *active_remote;
	char *rtpmap;
	char *fmtp;
	char *server_session;
	unsigned char aesiv[16];
	unsigned char aeskey[16];
	int   timing_port; //tport
	int   control_port; //cport
	int   server_port; //dport
	double volume;
	int   teardown;
	int   flush;
	int	  rtp_sockets[3];
};
*/


#endif
