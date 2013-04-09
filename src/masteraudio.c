#ifndef _MASTERAUDIO_SRC_
#define _MASTERAUDIO_SRC_

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <math.h>
#include <sys/stat.h>
#include <time.h>
#include <ao/ao.h>

#include "masteraudio.h"

#define MASTER_BUFFER_NUM_FRAMES (44100*60)
#define AO_NUM_BITS 16
#define AO_SAMPLE_RATE 44100
#define AO_NUM_CHANNELS 2

#define MASTER_BUFFER_SIZE (MASTER_BUFFER_NUM_FRAMES*AO_NUM_CHANNELS*sizeof(signed short))

#define AO_PLAY_RTP_TICKS (44100/50)
#define AO_PLAY_NUM_BYTES (AO_PLAY_RTP_TICKS*AO_NUM_CHANNELS*sizeof(signed short))

// libao stuff
static ao_device *dev = NULL;
char *libao_driver = NULL;
char *libao_devicename = NULL;
char *libao_deviceid = NULL; // ao_options expects "char*"

// pthread stuff
static pthread_t ao_thread = 0;

// Audio buffer stuff
void *ao_thread_func( void *arg );
static pthread_mutex_t master_abuf_mutex = PTHREAD_MUTEX_INITIALIZER;

// Timing stuff
static uint32_t master_rtp_time = 0;
static struct timespec ao_play_time = { 0, 0 };


// buffer stuff
static char *master_output_buffer = NULL;
static char *master_write_pointer = NULL;

int init_audio(void)
{
	int retval = 0;

	if( ao_thread != 0 )
		return retval;

	ao_initialize();

	master_output_buffer = malloc(MASTER_BUFFER_SIZE);
	memset( master_output_buffer, 0, MASTER_BUFFER_SIZE );
   
	int driver;
    
	if (libao_driver) {
        
		// if a libao driver is specified on the command line, use that
		driver = ao_driver_id(libao_driver);

		if (driver == -1) 
		{
			debugp( DEBUGP_AUDIO_OUTPUT, 0, "Could not find requested ao driver" );
			kill( getpid(), SIGINT );
		}
	} 
	else 
	{
		// otherwise choose the default
		driver = ao_default_driver_id();
	}

	ao_sample_format fmt;
	memset(&fmt, 0, sizeof(fmt));
	
	fmt.bits = AO_NUM_BITS;
	fmt.rate = AO_SAMPLE_RATE;
   fmt.channels = AO_NUM_CHANNELS;
   fmt.byte_format = AO_FMT_NATIVE;
	
    
	ao_option *ao_opts = NULL;
    
	if(libao_deviceid) 
	{
		ao_append_option(&ao_opts, "id", libao_deviceid);
	} 
	else if(libao_devicename)
	{
        
		ao_append_option(&ao_opts, "dev", libao_devicename);
		
		// Old libao versions (for example, 0.8.8) only support
		// "dsp" instead of "dev".
		ao_append_option(&ao_opts, "dsp", libao_devicename);
	}

	dev = ao_open_live(driver, &fmt, ao_opts);

	if (dev == NULL) 
	{
		debugp( DEBUGP_AUDIO_OUTPUT, 0, "Could not open ao device (%d)", errno);
		kill( getpid(), SIGINT );
	}

	if(pthread_create( &ao_thread, NULL, ao_thread_func, NULL ))
	{
		debugp( DEBUGP_AUDIO_OUTPUT, 0, "Could not start ao_thread\n" );
		kill( getpid(), SIGINT );
	}

	return retval;
}

/**
 * This theoretically returns the master RTP time of the audio currently playing 
 * this very moment. This has to be extrapolated, given the time we started playing
 * audio and the current time.
 */
uint32_t get_master_rtp_time(void)
{
	uint32_t rtptime;
	struct timespec playtime,nowtime;
	
	// Get our own copies of the data to work with
	pthread_mutex_lock( &master_abuf_mutex );
	rtptime = master_rtp_time;
	memcpy( &playtime, &ao_play_time, sizeof(struct timespec) );
	pthread_mutex_unlock( &master_abuf_mutex );

	// Get the current time
	clock_gettime( CLOCK_REALTIME, &nowtime );

	// Calculate how many RTP ticks have passed since ao_play started
	double playtimef = (double)playtime.tv_sec + (double)playtime.tv_nsec / (double)1000000000;
	double nowtimef = (double)nowtime.tv_sec + (double)nowtime.tv_nsec / (double)1000000000;
	double deltaf = nowtimef - playtimef; // fractional seconds

	// There are AO_SAMPLE_RATE rtp ticks per second (44.100kHz)
	uint32_t delta_rtp = deltaf * (double)AO_SAMPLE_RATE;

	rtptime += delta_rtp;

	return rtptime;
}

/** 
 * This function returns a pointer to some location in the master buffer which
 * corresponds to a local RTP time
 */
char *get_master_pointer_by_rtp_time( uint32_t rtptime, uint32_t *lateby )
{
	uint32_t rtpnow;
	char *p = NULL;
	char *mwp = NULL;
	
	// Get our own copies of the data to work with
	pthread_mutex_lock( &master_abuf_mutex );
	rtpnow = master_rtp_time;
	mwp = master_write_pointer;	
	pthread_mutex_unlock( &master_abuf_mutex );

	// rtpnow is the rtp time that ao_play started playing.
	// the master_write_pointer points to the location just after the portion of
	// buffer given to ao_play. So, the first legal pointer we can return has to be 
	// after master_write_pointer
	
	// Lets figure out the rtp time of the location of master_write_pointer
	uint32_t master_write_rtp = rtpnow + AO_PLAY_RTP_TICKS;

	// If the requested rtp time is before this time, we're late
	// rtp time is an unsigned 32-bit integer designed to overflow frequently. Be careful
	// about comparisons
	int rtpdiff = rtptime - master_write_rtp;
	if( rtpdiff < 0 )
	{
		*lateby = -1 * rtpdiff;
		p = mwp;
	}
	else
	{
		*lateby = 0; // not late; either on-time or early

		// We are rtpdiff ticks ahead of the master_write_rtp. Calculate how many bytes 
		// this corresponds to
		p = mwp + ( rtpdiff * AO_NUM_CHANNELS * sizeof(signed short) );

		// Check for overflow
		if( (p - master_output_buffer) >= MASTER_BUFFER_SIZE )
		{
			p -= MASTER_BUFFER_SIZE;
		}
	}

	return p;
}

void composite_audio_samples( short *original, short *new, int count )
{
	static unsigned int next_print = 0;

	// Attenuate each by some dB
	// FIXME: This is redundant!
	double atten = 20.0 * log10( 0.5 );
	double gain = pow( 10.0, atten / 20.0 );

	for( int i = 0; i < count; i++ )
	{
		short sample1 = *original;
		short sample2 = *new;
		short mixed = 0;

		if( sample1 == 0 )
			mixed = sample2;
		else if( sample2 == 0 )
			mixed = sample1;
		else 
		{

			sample1 *= gain;
			sample2 *= gain;

			unsigned long s1,s2,m=0;

			s1 = 0x7fff + sample1;
			s2 = 0x7fff + sample2;

			if( (s1 < 0x7fff) && (s2 < 0x7fff) )
			{
				m = s1 * s2 / 0x7fff;
			}
			else
			{
				m = 2 * (s1 + s2) - s1 * s2 / 0x7fff - 0xfffe;
			}

			int premixed = (int)m - 0x7fff;
			
			if( premixed > 32767 )
				mixed = 32767;
			else if( premixed < -32768 )
				mixed = -32768;
			else
				mixed = premixed;
			
			//if( next_print == 0 )
			if( mixed > 30000 )
			{
				debugp( DEBUGP_AUDIO_OUTPUT, 7, "audio mixing: sample1= %6d sample2=%6d\n", sample1, sample2 );
				debugp( DEBUGP_AUDIO_OUTPUT, 7, "audio mixing: s1=      %6u s2=     %6u\n", s1, s2 );
				debugp( DEBUGP_AUDIO_OUTPUT, 7, "audio mixing: m=    %6u\n", m );
				debugp( DEBUGP_AUDIO_OUTPUT, 7, "audio mixing: mixed=%6d\n", mixed );
				debugp( DEBUGP_AUDIO_OUTPUT, 7, "\n" );
			}


		}
		*original = mixed;

		if( next_print == 0 )
			next_print = 1000;
		else
			next_print--;

		original++;
		new++;
	}
	return;
}
void composite_audio_samples2( short *original, short *new, int count )
{
	static unsigned int next_print = 0;

	for( int i = 0; i < count; i++ )
	{
		short sample1 = *original;
		short sample2 = *new;

		if( next_print == 0 )
			debugp( DEBUGP_AUDIO_OUTPUT, 7, "audio mixing: original=%6d new=%6d ", sample1, sample2 );

		sample1 >>= 1;
		sample2 >>= 1;
		
		*original = sample1 + sample2;
		
		if( next_print == 0 )
			debugp( DEBUGP_AUDIO_OUTPUT, 7, "mixed=%6d\n", *original );

		if( next_print == 0 )
			next_print = 1000;
		else
			next_print--;

		original++;
		new++;
	}
	return;
}

char *write_to_master_buffer( char *buffer, int num_frames, char *bptr )
{
	pthread_mutex_lock( &master_abuf_mutex );

	// Find startpoint
	int write_size = num_frames * AO_NUM_CHANNELS * sizeof(signed short);
	char *start = master_write_pointer;
	if( bptr )
		start = bptr;

	if( (start-master_output_buffer) >= MASTER_BUFFER_SIZE )
	{
		start -= MASTER_BUFFER_SIZE;
	}

	if( (start + write_size) >= (master_output_buffer+MASTER_BUFFER_SIZE) )
	{
		debugp( DEBUGP_AUDIO_OUTPUT, 3, "wrapping while writing to master output buffer\n" );
		int first_write_size = MASTER_BUFFER_SIZE - (start - master_output_buffer);
		int second_write_size = write_size - first_write_size;
	
		composite_audio_samples( (short*)start, (short*)buffer, first_write_size/2 );
		//memcpy( start, buffer, first_write_size );

		//memcpy( master_output_buffer, buffer + first_write_size, second_write_size );
		composite_audio_samples( (short*)master_output_buffer, (short*)(buffer + first_write_size), second_write_size/2 );
	}
	else
	{
		//memcpy( start, buffer, write_size );
		composite_audio_samples( (short*)start, (short*)buffer, write_size/2 );
	}

	char *end = start + write_size;
	if( (end-master_output_buffer) >= MASTER_BUFFER_SIZE )
		end -= MASTER_BUFFER_SIZE;

	pthread_mutex_unlock( &master_abuf_mutex );

	return end;
}

void ao_play_wrapper( ao_device *dev, char *buffer, int len )
{

//	signed short *c = (signed short*)buffer;
//	
//	for( int i=0; i < len/4; i++ )
//	{
//		debugp( DEBUGP_AUDIO_OUTPUT, 1, "%d,%d\n", *c++, *c++ );
//	}
	ao_play( dev, buffer, len );
	return;
}

void* ao_thread_func( void* arg )
{
	
	pthread_mutex_lock( &master_abuf_mutex );
	master_rtp_time = 0;
	pthread_mutex_unlock( &master_abuf_mutex );

	char *ao_play_pointer = master_output_buffer;
	master_write_pointer = master_output_buffer + AO_PLAY_NUM_BYTES;

	while(1)
	{

		// Lock mutex during these changes
		pthread_mutex_lock( &master_abuf_mutex );

		// Zero whatever we just played
		if( (ao_play_pointer + AO_PLAY_NUM_BYTES) >= (master_output_buffer+MASTER_BUFFER_SIZE) )
		{
			memset( ao_play_pointer, 0, MASTER_BUFFER_SIZE - (ao_play_pointer-master_output_buffer) );
			memset( master_output_buffer, 0, AO_PLAY_NUM_BYTES - (MASTER_BUFFER_SIZE - (ao_play_pointer-master_output_buffer)) );
		}
		else
		{
			memset( ao_play_pointer, 0, AO_PLAY_NUM_BYTES );
		}

		// Move the pointers up
		ao_play_pointer += AO_PLAY_NUM_BYTES;
		master_write_pointer += AO_PLAY_NUM_BYTES;

		// Check for overflow
		if( (ao_play_pointer - master_output_buffer) >= MASTER_BUFFER_SIZE )
		{
			ao_play_pointer -= MASTER_BUFFER_SIZE;
		}
		if( (master_write_pointer - master_output_buffer) >= MASTER_BUFFER_SIZE )
		{
			master_write_pointer -= MASTER_BUFFER_SIZE;
		}

		// Update our rtp time
		master_rtp_time += AO_PLAY_RTP_TICKS;
	
		// Unlock now that our pointers are all set
		pthread_mutex_unlock( &master_abuf_mutex );

		// Set ao_play_time
		clock_gettime( CLOCK_REALTIME, &ao_play_time );

		// Play audio
		if( (ao_play_pointer + AO_PLAY_NUM_BYTES) >= (master_output_buffer+MASTER_BUFFER_SIZE) )
		{
			debugp( DEBUGP_AUDIO_OUTPUT, 3, "ao_play wrapping\n" );
			ao_play_wrapper( dev, ao_play_pointer, MASTER_BUFFER_SIZE - (ao_play_pointer-master_output_buffer) );

			ao_play_wrapper( dev, master_output_buffer, AO_PLAY_NUM_BYTES - (MASTER_BUFFER_SIZE - (ao_play_pointer-master_output_buffer)) );
		}
		else
		{
			ao_play_wrapper( dev, ao_play_pointer, AO_PLAY_NUM_BYTES );
		}
		

		//debugp( DEBUGP_AUDIO_OUTPUT, 4, "%d frames took %f seconds\n", AO_PLAY_RTP_TICKS, diff );
	}
	pthread_exit(NULL);
}

#endif
