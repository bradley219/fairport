/*
 * HairTunes - RAOP packet handler and slave-clocked replay engine
 * Copyright (c) James Laird 2011
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <math.h>
#include <sys/stat.h>
#include <time.h>

#include "ao.h"
#include "session.h"
#include "hairtunes.h"
#include <sys/signal.h>
#include <fcntl.h>
#include <ao/ao.h>
#include "debugp.h"

#ifdef FANCY_RESAMPLING
#include <samplerate.h>
#endif

#include <assert.h>
int debug = 1;

#include "alac.h"

// and how full it needs to be to begin (must be <BUFFER_FRAMES)

static pthread_t rtp_thread = 0;
static int rtp_sock = 0;
static int rtp_csock = 0;
static int rtp_tsock = 0;

static pthread_mutex_t ao_play_mutex = PTHREAD_MUTEX_INITIALIZER;

#define FRAME_BYTES (4*sess->frame_size)
// maximal resampling shift - conservative
#define OUTFRAME_BYTES (4*(sess->frame_size+3))

//alac_file *decoder_info;

#ifdef FANCY_RESAMPLING
#error "FANCY_RESAMPLING ENABLED"
int fancy_resampling = 1;
SRC_STATE *src;
#endif

// functions
int init_rtp(void);
void init_buffer(struct session *sess);
pthread_t *init_output( struct session *sess );
void rtp_request_resend(seq_t first, seq_t last, struct session *sess );
void ab_resync(struct session *sess);

// interthread variables
  // stdin->decoder

//volatile abuf_t audio_buffer[BUFFER_FRAMES];
#define BUFIDX(seqno) ((seq_t)(seqno) % BUFFER_FRAMES)

// mutex-protected variables
//volatile seq_t ab_read, ab_write;
//int ab_buffering = 1;
//int ab_synced = 0;

void die(char *why) 
{
    fprintf(stderr, "FATAL: %s\n", why);
	kill( getpid(), SIGINT );
}

int init_decoder( int *fmtp, struct session *sess ) 
{
    alac_file *alac;

    sess->frame_size = fmtp[1]; // stereo samples
    sess->sampling_rate = fmtp[11];

    int sample_size = fmtp[3];
    if (sample_size != 16)
        die("only 16-bit samples supported!");

    alac = create_alac(sample_size, 2);
    if (!alac)
        return 1;
    sess->decoder_info = alac;

    alac->setinfo_max_samples_per_frame = sess->frame_size;
    alac->setinfo_7a = fmtp[2];
    alac->setinfo_sample_size = sample_size;
    alac->setinfo_rice_historymult = fmtp[4];
    alac->setinfo_rice_initialhistory = fmtp[5];
    alac->setinfo_rice_kmodifier = fmtp[6];
    alac->setinfo_7f = fmtp[7];
    alac->setinfo_80 = fmtp[8];
    alac->setinfo_82 = fmtp[9];
    alac->setinfo_86 = fmtp[10];
    alac->setinfo_8a_rate = fmtp[11];
    allocate_buffers(alac);
    return 0;
}

void *hairtunes_thread( void *parg )
{
	struct session *sess = (struct session*)parg;
	pthread_mutex_lock( sess->cc_mutex );
	
//	debugp( DEBUGP_DEFAULT, 7, "hairtunes pthread_mutex_lock( sess->cc_param_changed_mutex );\n" );
//	pthread_mutex_lock( sess->cc_param_changed_mutex );

    //AES_set_decrypt_key(sess->aeskey, 128, &sess->aes);

	int fmtp[32];
    memset(fmtp, 0, sizeof(fmtp));
    int i = 0;
    char *arg;
    while ( (arg = strsep(&sess->fmtp, " \t")) )
        fmtp[i++] = atoi(arg);

	// Wait for volume parameter
    init_decoder(fmtp,sess);
	debugp( DEBUGP_DEFAULT, 7, "init_decoder()\n" );
    init_buffer(sess);
	debugp( DEBUGP_DEFAULT, 7, "init_buffer()\n" );
    
	int rtp = init_rtp(); // start the rtp thread
	if( rtp == 1 )
		debugp( DEBUGP_DEFAULT, 7, "init_rtp()..already started\n" );
	else if( rtp == 0 )
		debugp( DEBUGP_DEFAULT, 7, "init_rtp()..started\n" );
	else
	{
		debugp( DEBUGP_DEFAULT, 0, "init_rtp() returned %d\n", rtp );
		exit(-1);
	}
	
	pthread_mutex_unlock( sess->cc_mutex );
    pthread_t *audio_thread = init_output(sess); // resample and output from ring buffer
	pthread_mutex_lock( sess->cc_mutex );
	debugp( DEBUGP_DEFAULT, 7, "init_output()\n" );

	debugp( DEBUGP_DEFAULT, 7, "Session %08X hairtunes thread is ready. Signaling...\n", sess->id );
	fflush(stderr);
	pthread_mutex_lock( sess->ht_ready_mutex );
	pthread_cond_signal( sess->ht_ready );
	pthread_mutex_unlock( sess->ht_ready_mutex );

    double f = 0;
	pthread_mutex_unlock( sess->cc_mutex );
	while(1) 
	{
		pthread_mutex_lock( sess->cc_param_changed_mutex );
		
		debugp( DEBUGP_DEFAULT, 6, "Session %08X Waiting for signal...\n", sess->id );
		pthread_cond_wait( sess->cc_param_changed, sess->cc_param_changed_mutex );
		pthread_mutex_unlock( sess->cc_param_changed_mutex );

		pthread_mutex_lock( sess->cc_mutex );

		// Read for changed values
		if( f != sess->volume )
		{
			debugp( DEBUGP_DEFAULT, 5, "Session %08X Volume has changed to %lf!\n", sess->id, sess->volume );
			f = sess->volume;
			assert(f<=0);
            //sess->volume = pow(10.0,0.05*f);
			
			pthread_mutex_lock( sess->vol_mutex );
            sess->fix_volume = 65536.0 * pow(10.0,0.05*f);
			debugp( DEBUGP_DEFAULT, 7, "Session %08X fix_volume = %lu\n", sess->id, sess->fix_volume );
			pthread_mutex_unlock( sess->vol_mutex );
		}
		if( sess->teardown )
		{
			debugp( DEBUGP_DEFAULT, 5, "Teardown request received. waiting for threads to close\n" );  // TODO: kill all child threads, exit the thread gracefully
			pthread_mutex_unlock( sess->cc_mutex );

			pthread_join( rtp_thread, NULL ); // FIXME
			debugp( DEBUGP_DEFAULT, 5, "rtp_thread finished\n" );
			pthread_join( *audio_thread, NULL );
			debugp( DEBUGP_DEFAULT, 5, "audio_thread finished\n" );
			break;
		}
		if( sess->flush )
		{
			debugp( DEBUGP_DEFAULT, 5, "Flush request received!\n" );
           
			pthread_mutex_lock(sess->ab_mutex);
            ab_resync(sess);
            pthread_mutex_unlock(sess->ab_mutex);
            if (debug)
                fprintf(stderr, "FLUSH\n");
		
			sess->flush = 0;
		}
		pthread_mutex_unlock( sess->cc_mutex );
	}
	free(audio_thread);

	debugp( DEBUGP_DEFAULT, 7, "Session %08A hairtunes_thread exiting\n", sess->id );

	pthread_exit(NULL);
}

void init_buffer( struct session *sess ) 
{
    int i;
    for (i=0; i<BUFFER_FRAMES; i++)
        sess->audio_buffer[i].data = malloc(OUTFRAME_BYTES);
    ab_resync(sess);
}

void ab_resync( struct session *sess ) 
{
    int i;
    for (i=0; i<BUFFER_FRAMES; i++)
        sess->audio_buffer[i].ready = 0;
    sess->ab_synced = 0;
    sess->ab_buffering = 1;
}

// the sequence numbers will wrap pretty often.
// this returns true if the second arg is after the first
static inline int seq_order(seq_t a, seq_t b) 
{
    signed short d = b - a;
    return d > 0;
}

void alac_decode(struct session *sess, short *dest, char *buf, int len) 
{
    unsigned char packet[MAX_PACKET];
    assert(len<=MAX_PACKET);

    unsigned char iv[16];
    int i;
    memcpy(iv, sess->aesiv, sizeof(iv));
    for (i=0; i+16<=len; i += 16)
        AES_cbc_encrypt((unsigned char*)buf+i, packet+i, 0x10, &sess->aes, iv, AES_DECRYPT);
    if (len & 0xf)
        memcpy(packet+i, buf+i, len & 0xf);

    int outsize;

    decode_frame(sess->decoder_info, packet, dest, &outsize);

    assert(outsize == FRAME_BYTES);
}

void buffer_put_packet( seq_t seqno, char *data, int len, struct session *sess) 
{
	//debugp( DEBUGP_DEFAULT, 7, "Session %08X buffer_put_packet() ", sess->id );
    volatile abuf_t *abuf = 0;
    short read;
    short buf_fill;

    pthread_mutex_lock(sess->ab_mutex);
    if (!sess->ab_synced) {
        sess->ab_write = seqno;
        sess->ab_read = seqno-1;
        sess->ab_synced = 1;
    }
    if (seqno == sess->ab_write+1) {                  // expected packet
        abuf = sess->audio_buffer + BUFIDX(seqno);
        sess->ab_write = seqno;
    } else if (seq_order(sess->ab_write, seqno)) {    // newer than expected
        rtp_request_resend(sess->ab_write, seqno-1,sess);
        abuf = sess->audio_buffer + BUFIDX(seqno);
        sess->ab_write = seqno;
    } else if (seq_order(sess->ab_read, seqno)) {     // late but not yet played
        abuf = sess->audio_buffer + BUFIDX(seqno);
    } else {    // too late.
		debugp( DEBUGP_DEFAULT, 3, "\nSession %08X late packet %04X (%04X:%04X)\n", sess->id, seqno, sess->ab_read, sess->ab_write);
    }
    buf_fill = sess->ab_write - sess->ab_read;
    pthread_mutex_unlock(sess->ab_mutex);

    if (abuf) {
        alac_decode(sess,abuf->data, data, len);
        abuf->ready = 1;
    }

    if (sess->ab_buffering && buf_fill >= sess->buffer_start_fill) {
        sess->ab_buffering = 0;
    	pthread_mutex_lock(sess->ab_mutex); // XXX
        pthread_cond_signal(sess->ab_buffer_ready);
    	pthread_mutex_unlock(sess->ab_mutex); // XXX
    }
    if (!sess->ab_buffering) {
        // check if the t+10th packet has arrived... last-chance resend
        read = sess->ab_read + 10;
        abuf = sess->audio_buffer + BUFIDX(read);
        if (abuf->ready != 1) {
            rtp_request_resend(read, read,sess);
            abuf->ready = -1;
        }
    }
}

void *rtp_thread_func(void *arg) 
{

	struct sockaddr_storage rtp_client;
	socklen_t si_len = sizeof(struct sockaddr_in);
    char packet[MAX_PACKET];
    char *pktp;
    seq_t seqno;
    
	int sock = rtp_sock; //sess->sock;
	int csock = rtp_csock; //sess->csock;
	int tsock = rtp_tsock; //sess->tsock;
    
    char type;

	int highsock = 0;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
	if(sock>highsock)
		highsock = sock;
    FD_SET(csock, &fds);
	if(csock>highsock)
		highsock = csock;
    FD_SET(tsock, &fds);
	if(tsock>highsock)
		highsock = tsock;

    while(1)
	{
		struct timeval timeout = {.tv_sec = 1,.tv_usec=0};
		int ready = select( 
				highsock + 1,
				&fds, NULL, NULL, 
				&timeout
				);
		if( ready < 0 )
		{
			debugp( DEBUGP_DEFAULT, 1, "select returned %d\n", ready );
			break;
		}
//		else if( ready == 0 ) // timed out, check for teardown
//		{
//			//pthread_mutex_lock( sess->cc_mutex );
//			if( sess->teardown )
//			{
//				debugp( DEBUGP_DEFAULT, 7, "rtp_thread_func got sess->teardown = %d. cleaning up..\n", sess->teardown );
//				close(sock); 
//				close(csock); 
//				close(tsock); 
//
//				// FIXME: this aint right
//				//pthread_mutex_lock(sess->ab_mutex);
//				//pthread_cond_signal(sess->ab_buffer_ready);
//				//pthread_mutex_unlock(sess->ab_mutex);
//
//				//pthread_mutex_unlock( sess->cc_mutex );
//				break;
//			}
//			else
//				pthread_mutex_unlock( sess->cc_mutex );
//		}
		else
		{
			int readsock = 0;
			if (FD_ISSET(sock, &fds)) {
				readsock = sock;
			} else if(FD_ISSET(csock, &fds)) {
				readsock = csock;
			}

    		ssize_t plen;
			if( readsock > 0 )
			{
				plen = recvfrom( readsock, packet, sizeof(packet), 0, (struct sockaddr*)&rtp_client, &si_len);

			
				// Find the session that this packet belongs to
				struct session *session = NULL;
				for( struct session *s = get_first_session(); s != NULL; s = s->next )
				{
					if( 
							((struct sockaddr_in*)&rtp_client)->sin_addr.s_addr ==
							((struct sockaddr_in*)s->rtp_client)->sin_addr.s_addr )
					{
						session = s;
						//debugp( DEBUGP_DEFAULT, 7, "received from ip %lx session %08X; dev=%p\n", 
						//		((struct sockaddr_in*)&rtp_client)->sin_addr.s_addr,
						//		session->id,
						//		session->dev
						//		);
						break;
					}
				}
				if( session == NULL )
				{
					debugp( DEBUGP_DEFAULT, 7, "received from ip %lx SESSION NOT FOUND\n", ((struct sockaddr_in*)&rtp_client)->sin_addr.s_addr );
				}

				if (plen < 0)
					continue;
				assert(plen<=MAX_PACKET);

				type = packet[1] & ~0x80;
				if (type == 0x60 || type == 0x56) {   // audio data / resend
					pktp = packet;
					if (type==0x56) {
						pktp += 4;
						plen -= 4;
					}
					seqno = ntohs(*(unsigned short *)(pktp+2));
					buffer_put_packet(seqno, pktp+12, plen-12, session );
				}
			}
			if( FD_ISSET(tsock,&fds) )
			{
				plen = recvfrom( tsock, packet, sizeof(packet), 0, (struct sockaddr*)&rtp_client, &si_len);
				if(plen<0)
					continue;

				debugp( DEBUGP_DEFAULT, 7, "received timing packet (%d bytes): ", plen );
				
				char *p = packet;
				while(plen--)
				{
					debugp( DEBUGP_DEFAULT, 7, "[%02x]", *p++ );
				}
				debugp( DEBUGP_DEFAULT, 7, "\n" );
			}

			FD_SET(sock, &fds);
			FD_SET(csock, &fds);
			FD_SET(tsock, &fds);
		}
    }

	pthread_exit(NULL);
    //return 0;
}

void rtp_request_resend(seq_t first, seq_t last, struct session *sess ) 
{
    if (seq_order(last, first))
        return;

    fprintf(stderr, "Session %08X requesting resend on %d packets (port %d)\n", sess->id, last-first+1, sess->control_port);

    char req[8];    // *not* a standard RTCP NACK
    req[0] = 0x80;
    req[1] = 0x55|0x80;  // Apple 'resend'
    *(unsigned short *)(req+2) = htons(1);  // our seqnum
    *(unsigned short *)(req+4) = htons(first);  // missed seqnum
    *(unsigned short *)(req+6) = htons(last-first+1);  // count

#ifdef AF_INET6
    ((struct sockaddr_in6*)sess->rtp_client)->sin6_port = htons(sess->control_port);
#else
    ((struct sockaddr_in*)sess->rtp_client)->sin_port = htons(sess->control_port);
#endif

    sendto( rtp_csock, req, sizeof(req), 0, (struct sockaddr *)&sess->rtp_client, sizeof(sess->rtp_client));
}

int init_rtp(void)
{
	if( rtp_thread != 0 )
		return 1;

    struct sockaddr_in si;
    int type = AF_INET;
	struct sockaddr* si_p = (struct sockaddr*)&si;
	socklen_t si_len = sizeof(si);
    
	unsigned short *sin_port = &si.sin_port;
    memset(&si, 0, sizeof(si));

#ifdef AF_INET6
    struct sockaddr_in6 si6;
    type = AF_INET6;
	si_p = (struct sockaddr*)&si6;
	si_len = sizeof(si6);
    sin_port = &si6.sin6_port;
    memset(&si6, 0, sizeof(si6));
#endif

    si.sin_family = AF_INET;
#ifdef SIN_LEN
	si.sin_len = sizeof(si);
#endif
    si.sin_addr.s_addr = htonl(INADDR_ANY);
#ifdef AF_INET6
    si6.sin6_family = AF_INET6;
    #ifdef SIN6_LEN
        si6.sin6_len = sizeof(si);
    #endif
    si6.sin6_addr = in6addr_any;
    si6.sin6_flowinfo = 0;
#endif

    int sock = -1, csock = -1;    // data and control (we treat the streams the same here)
	int tsock = -1;
    
	while(1) 
	{
        if(sock < 0)
            sock = socket(type, SOCK_DGRAM, IPPROTO_UDP);
#ifdef AF_INET6
	    if(sock==-1 && type == AF_INET6) {
	        // try fallback to IPv4
	        type = AF_INET;
	        si_p = (struct sockaddr*)&si;
	        si_len = sizeof(si);
	        sin_port = &si.sin_port;
	        continue;
	    }
#endif
        if (sock==-1)
            die("Can't create data socket!");

        if(csock < 0)
            csock = socket(type, SOCK_DGRAM, IPPROTO_UDP);
        if (csock==-1)
            die("Can't create control socket!");

		if( tsock < 0 )
			tsock = socket(type, SOCK_DGRAM, IPPROTO_UDP);
		if(tsock==-1)
			die("Can't create timing socket!");

        //*sin_port = htons(port);
		//pthread_mutex_lock( sess->cc_mutex );

        //*sin_port = htons(sess->server_port);
        *sin_port = htons(6000);
        int sbind = bind(sock, si_p, si_len);
        
		//*sin_port = htons(sess->control_port);
		*sin_port = htons(6001);
        int cbind = bind(csock, si_p, si_len);
        
		//*sin_port = htons(sess->timing_port);
		*sin_port = htons(6002);
		int tbind = bind(tsock, si_p, si_len);

		//pthread_mutex_unlock( sess->cc_mutex );
        
		if(sbind != -1 && cbind != -1 && tbind != -1) 
		{
			break;
		}
        if(sbind != -1) { 
			close(sock); 
			sock = -1; 
		}
        if(cbind != -1) { 
			close(csock); 
			csock = -1; 
		}
		if(tbind != -1) {
			close(tsock);
			tsock = -1;
		}

		//pthread_mutex_lock( sess->cc_mutex );
		debugp( DEBUGP_DEFAULT, 1, "bind failed on one or more UDP ports\n" );
		exit(-1);

		//(sess->server_port)+=3;
		//(sess->control_port)+=3;
		//(sess->timing_port)+=3;
		//pthread_mutex_unlock( sess->cc_mutex );
    }

    //pthread_t *rtp_thread = malloc(sizeof(pthread_t));
    rtp_sock = sock;
    rtp_csock = csock;
    rtp_tsock = tsock;

    return pthread_create( &rtp_thread, NULL, rtp_thread_func, NULL );
}

static inline short dithered_vol(short sample,struct session *sess) 
{
    static short rand_a, rand_b;
    long out;
    rand_b = rand_a;
    rand_a = rand() & 0xffff;

    out = (long)sample * sess->fix_volume;
    if (sess->fix_volume < 0x1000) {
        out += rand_a;
        out -= rand_b;
    }
    return out>>16;
}

static void biquad_init(biquad_t *bq, double a[], double b[]) 
{
    bq->hist[0] = bq->hist[1] = 0.0;
    memcpy(bq->a, a, 2*sizeof(double));
    memcpy(bq->b, b, 3*sizeof(double));
}

static void biquad_lpf(biquad_t *bq, double freq, double Q, struct session *sess) 
{
    double w0 = 2*M_PI*freq/((float)sess->sampling_rate/(float)sess->frame_size);
    double alpha = sin(w0)/(2.0*Q);

    double a_0 = 1.0 + alpha;
    double b[3], a[2];
    b[0] = (1.0-cos(w0))/(2.0*a_0);
    b[1] = (1.0-cos(w0))/a_0;
    b[2] = b[0];
    a[0] = -2.0*cos(w0)/a_0;
    a[1] = (1-alpha)/a_0;

    biquad_init(bq, a, b);
}

static double biquad_filt(biquad_t *bq, double in) 
{
    double w = in - bq->a[0]*bq->hist[0] - bq->a[1]*bq->hist[1];
    double out __attribute__((unused)) = bq->b[1]*bq->hist[0] + bq->b[2]*bq->hist[1] + bq->b[0]*w;
    bq->hist[1] = bq->hist[0];
    bq->hist[0] = w;

    return w;
}

void bf_est_reset(short fill, struct session *sess) 
{
    biquad_lpf(&sess->bf_drift_lpf, 1.0/180.0, 0.3,sess);
    biquad_lpf(&sess->bf_err_lpf, 1.0/10.0, 0.25,sess);
    biquad_lpf(&sess->bf_err_deriv_lpf, 1.0/2.0, 0.2,sess);
    sess->fill_count = 0;
    sess->bf_playback_rate = 1.0;
    sess->bf_est_err = sess->bf_last_err = 0;
    sess->desired_fill = sess->fill_count = 0;
}
void bf_est_update(short fill, struct session *sess) 
{
    if (sess->fill_count < 1000) {
        sess->desired_fill += (double)fill/1000.0;
        (sess->fill_count)++;
        return;
    }

#define CONTROL_A   (1e-4)
#define CONTROL_B   (1e-1)

    double buf_delta = fill - sess->desired_fill;
    sess->bf_est_err = biquad_filt(&sess->bf_err_lpf, buf_delta);
    double err_deriv = biquad_filt(&sess->bf_err_deriv_lpf, sess->bf_est_err - sess->bf_last_err);

    sess->bf_est_drift = biquad_filt(&sess->bf_drift_lpf, CONTROL_B*(sess->bf_est_err*CONTROL_A + err_deriv) + sess->bf_est_drift);

    if (debug>1)
        fprintf(stderr, "bf %d err %f drift %f desiring %f ed %f estd %f\r", fill, sess->bf_est_err, sess->bf_est_drift, sess->desired_fill, err_deriv, err_deriv + CONTROL_A*sess->bf_est_err);
    sess->bf_playback_rate = 1.0 + CONTROL_A*sess->bf_est_err + sess->bf_est_drift;

    sess->bf_last_err = sess->bf_est_err;
}

#if BUFFERING_STYLE == 2
void *pthread_timeout( void *arg )
{
	struct session *sess = (struct session*)arg;
	struct timespec timeout = { .tv_sec = BUFFER_TIMEOUT, .tv_nsec = 0 };
	nanosleep( &timeout, NULL );
	pthread_mutex_lock( sess->ab_mutex );
	if(sess->ab_buffering)
	{
		pthread_cond_signal( sess->ab_buffer_ready );
	}
	pthread_mutex_unlock( sess->ab_mutex );

	pthread_exit(NULL);
}
#endif

// get the next frame, when available. return 0 if underrun/stream reset.
short *buffer_get_frame(struct session *sess) 
{
    short buf_fill;
    seq_t read;

	//debugp( DEBUGP_DEFAULT, 7, "Session %08X buffer_get_frame()\n", sess->id );

    pthread_mutex_lock(sess->ab_mutex);

    buf_fill = sess->ab_write - sess->ab_read;


    if (buf_fill < 1 || !sess->ab_synced || sess->ab_buffering) {    // init or underrun. stop and wait
		
		if(!sess->ab_synced)
            debugp( DEBUGP_DEFAULT, 3, "Session %08X syncing\n", sess->id );
		if(sess->ab_buffering)
            debugp( DEBUGP_DEFAULT, 3, "Session %08X buffering\n", sess->id );
		if(buf_fill<1)
			debugp( DEBUGP_DEFAULT, 3, "Session %08X buf_fill<1\n", sess->id );
        
		sess->ab_buffering = 1;

#if BUFFERING_STYLE == 1
        if (sess->ab_synced)
           debugp( DEBUGP_DEFAULT, 3, "\nSession %08X underrun.\n", sess->id );


		debugp( DEBUGP_DEFAULT, 7, "Session %08X pthread_cond_wait(ab_buffer_ready)\n", sess->id );
        pthread_cond_wait(sess->ab_buffer_ready, sess->ab_mutex);
        (sess->ab_read)++;
        buf_fill = sess->ab_write - sess->ab_read;
        pthread_mutex_unlock(sess->ab_mutex);

        bf_est_reset(buf_fill,sess);
        return 0;
#elif BUFFERING_STYLE == 2

		//struct timespec timeout = { .tv_sec = BUFFER_TIMEOUT, .tv_nsec = 0 };
		struct timespec start_time,now_time;
		clock_gettime( CLOCK_MONOTONIC_RAW, &start_time );
		double st = start_time.tv_sec + (double)start_time.tv_nsec / 1000000000.0;
		double nt;
		do {
			pthread_t thread;
			pthread_create( &thread, NULL, pthread_timeout, (void*)sess );
			/*
			pthread_cond_timedwait(
					&ab_buffer_ready,
					&ab_mutex,
					&timeout); 
					*/
			debugp( DEBUGP_DEFAULT, 7, "Session %08X pthread_cond_wait for ab_buffer_ready\n", sess->id, sess->ab_buffer_ready );
			pthread_cond_wait( sess->ab_buffer_ready, sess->ab_mutex );
			clock_gettime( CLOCK_MONOTONIC_RAW, &now_time );
			nt = now_time.tv_sec + (double)now_time.tv_nsec / 1000000000.0;
			if(debug)
				fprintf(stderr, 
						"ab_synced=%d ab_buffering=%d buf_fill=%d time=%lf\n", 
						sess->ab_synced,
						sess->ab_buffering,
						buf_fill,
						nt-st);
		} while( sess->ab_buffering && ((nt-st)<BUFFER_TIMEOUT) );

		if( (nt-st) >= BUFFER_TIMEOUT )
		{
			debugp( DEBUGP_DEFAULT, 5, "Session %08X Timed out while buffering. Tearing down\n", sess->id );
			sess->teardown = 1;
		}

        (sess->ab_read)++;
        buf_fill = sess->ab_write - sess->ab_read;
        pthread_mutex_unlock(sess->ab_mutex);

        bf_est_reset(buf_fill,sess);
        return 0;

#endif
    }
    if (buf_fill >= BUFFER_FRAMES) {   // overrunning! uh-oh. restart at a sane distance
        fprintf(stderr, "\noverrun.\n");
        sess->ab_read = sess->ab_write - START_FILL;
    }
    read = sess->ab_read;
    (sess->ab_read)++;
    pthread_mutex_unlock(sess->ab_mutex);

    buf_fill = sess->ab_write - sess->ab_read;
    bf_est_update(buf_fill,sess);

    volatile abuf_t *curframe = sess->audio_buffer + BUFIDX(read);
    if (curframe->ready != 1) {
        fprintf(stderr, "\nmissing frame.\n");
        memset(curframe->data, 0, FRAME_BYTES);
    }
    curframe->ready = 0;
	
    return curframe->data;
}

int stuff_buffer(double playback_rate, short *inptr, short *outptr, struct session *sess) 
{
    int i;
    int stuffsamp = sess->frame_size;
    int stuff = 0;
    double p_stuff;

    p_stuff = 1.0 - pow(1.0 - fabs(playback_rate-1.0), sess->frame_size);

    if ((float)rand()/((float)RAND_MAX) < p_stuff) {
        stuff = playback_rate > 1.0 ? -1 : 1;
        stuffsamp = rand() % (sess->frame_size - 1);
    }

	// Lock the mutex once here rather than lock/unlock for 
	// every single sample
	pthread_mutex_lock( sess->vol_mutex );
    for (i=0; i<stuffsamp; i++) {   // the whole frame, if no stuffing
        *outptr++ = dithered_vol(*inptr++,sess);
        *outptr++ = dithered_vol(*inptr++,sess);
    };
    if (stuff) {
        if (stuff==1) {
			debugp( DEBUGP_DEFAULT, 3, "Session %08X ++++++++++\n", sess->id );
            // interpolate one sample
            *outptr++ = dithered_vol(((long)inptr[-2] + (long)inptr[0]) >> 1,sess);
            *outptr++ = dithered_vol(((long)inptr[-1] + (long)inptr[1]) >> 1,sess);
        } else if (stuff==-1) {
			debugp( DEBUGP_DEFAULT, 3, "Session %08X -----------\n", sess->id );
            inptr++;
            inptr++;
        }
        for (i=stuffsamp; i<sess->frame_size + stuff; i++) {
            *outptr++ = dithered_vol(*inptr++,sess);
            *outptr++ = dithered_vol(*inptr++,sess);
        }
    }
	pthread_mutex_unlock( sess->vol_mutex );

    return sess->frame_size + stuff;
}

void *audio_thread_func(void *arg) 
{
	struct session *sess = (struct session*)arg;
	
    int play_samples;

    signed short buf_fill __attribute__((unused));
    signed short *inbuf = NULL;
	signed short *outbuf = NULL;
    outbuf = malloc(OUTFRAME_BYTES);

#ifdef FANCY_RESAMPLING
    float *frame, *outframe;
    SRC_DATA srcdat;
    if (fancy_resampling) {
        frame = malloc(sess->frame_size*2*sizeof(float));
        outframe = malloc(2*sess->frame_size*2*sizeof(float));

        srcdat.data_in = frame;
        srcdat.data_out = outframe;
        srcdat.input_frames = FRAME_BYTES;
        srcdat.output_frames = 2*FRAME_BYTES;
        srcdat.src_ratio = 1.0;
        srcdat.end_of_input = 0;
    }
#endif

    while (1) 
	{
        do {
			//debugp( DEBUGP_DEFAULT, 7, "Session %08X looping\n", sess->id );
			pthread_mutex_lock( sess->cc_mutex );
			if( sess->teardown )
			{
				debugp( DEBUGP_DEFAULT, 7, "Session %08X audio_thread sess->teardown; break\n", sess->id );
				pthread_mutex_unlock( sess->cc_mutex );
				break;
			}
			else
				pthread_mutex_unlock( sess->cc_mutex );
            
			inbuf = buffer_get_frame(sess);
			
			if(!inbuf)
				debugp( DEBUGP_DEFAULT, 7, "Session %08X inbuf is null\n", sess->id );

        } while (!inbuf);
		
		//debugp( DEBUGP_DEFAULT, 7, "Session %08X locking cc_mutex..", sess->id );
		pthread_mutex_lock( sess->cc_mutex );
		//debugp( DEBUGP_DEFAULT, 7, "locked\n" );
		if( sess->teardown )
		{
			debugp( DEBUGP_DEFAULT, 7, "Session %08X audio_thread_func got sess->teardown = %d. cleaning up..\n", sess->id, sess->teardown );
			
			//int closed = ao_close( sess->dev );

			//debugp( DEBUGP_DEFAULT, 7, "Session %08X ao_close exited with %d\n", sess->id, closed );
			pthread_mutex_unlock( sess->cc_mutex );
			break;
		}
		else
			pthread_mutex_unlock( sess->cc_mutex );

#ifdef FANCY_RESAMPLING
        if (fancy_resampling) {
	        int i;
            for (i=0; i<2*FRAME_BYTES; i++) {
                frame[i] = (float)inbuf[i] / 32768.0;
                frame[i] *= volume;
            }
            srcdat.src_ratio = sess->bf_playback_rate;
            src_process(src, &srcdat);
            assert(srcdat.input_frames_used == FRAME_BYTES);
            src_float_to_short_array(outframe, outbuf, FRAME_BYTES*2);
            play_samples = srcdat.output_frames_gen;
        } else {
            play_samples = stuff_buffer(sess->bf_playback_rate, inbuf, outbuf, sess);
		}
#else
		play_samples = stuff_buffer(sess->bf_playback_rate, inbuf, outbuf, sess);
#endif
		pthread_mutex_lock( &ao_play_mutex );

      //ao_play( sess->dev, (char *)outbuf, play_samples*4);
        
		play( (char *)outbuf, play_samples*4);
		pthread_mutex_unlock( &ao_play_mutex );

		(sess->ao_plays)++;

#if VU_METER_ENABLE == 1
		signed short *ob = outbuf;
		double rms_total = 0;
		int num_samples = 0;
		static unsigned short highest = 0;

		// Calculate RMS
		int s;
		for( s=0; s < play_samples; s++ )
		{
			ob++;
			signed short sample = *ob++;
			ob++;
			sample += *ob++;

			if(sample>highest)
				highest = sample;

			rms_total += pow( sample, 2 );
			num_samples+=2;
		}
		double rms = sqrt( rms_total / (double)num_samples );
		unsigned short bar;

		bar = rms * (double)SCREEN_WIDTH / (double)highest;
	
		for( s=0; s < bar; s++ )
			fprintf( stderr, "#" );
		for( s=0; s < (SCREEN_WIDTH-bar); s++ )
			fprintf( stderr, " " );
			
		fprintf( stderr, "\r" );

		//fprintf( stderr, "0x%04x left_bar = %u\tright_bar = %u\r",
		//		highest,
		//		left_bar,
		//		right_bar
		//		 );

		//fprintf( stderr, "rms_left = %lf\trms_right = %lf\n",
		//		rms_left,
		//		rms_right );
#else
//		if( !(sess->ao_plays % 100) )
//			debugp( DEBUGP_DEFAULT, 7, "Session %08X ao_plays = %lu\n", sess->id, sess->ao_plays );
#endif
		
    }
	free(outbuf);
	free(arg);
   
	pthread_exit(NULL);
	//return 0;
}


pthread_t *init_output( struct session *sess ) 
{

	init_ao(sess);

#ifdef FANCY_RESAMPLING
    int err;
    if (fancy_resampling)
        src = src_new(SRC_SINC_MEDIUM_QUALITY, 2, &err);
    else
        src = 0;
#endif

    pthread_t *audio_thread = malloc(sizeof(pthread_t));
    if( pthread_create(audio_thread, NULL, audio_thread_func, (void*)sess ) )
	{
		debugp( DEBUGP_DEFAULT, 0, "Failed to create audio_thread_func for session %08x\n", sess->id );
	}

    return audio_thread;
}
