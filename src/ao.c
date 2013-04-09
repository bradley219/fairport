#ifndef _FAIRPORT_AO_SOURCE_
#define _FAIRPORT_AO_SOURCE_
#include "ao.h"

// libao stuff
static ao_device *dev = NULL;
char *libao_driver = NULL;
char *libao_devicename = NULL;
char *libao_deviceid = NULL; // ao_options expects "char*"

// pthread stuff
static pthread_t ao_thread = 0;

static pthread_mutex_t bufmutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_mutex_t buftrig_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t buftrig = PTHREAD_COND_INITIALIZER;

void *ao_thread_func( void *arg );

// buffer stuff
static int output_buffer_size = 0;
static char *output_buffer = NULL;
static int bytes_in_buffer = 0;
static int buffer_ready = 0;



void init_ao( session_t *sess ) 
{
	if( ao_thread != 0 )
		return;

    ao_initialize();

	output_buffer_size = 4 * (sess->frame_size+3);
	output_buffer = malloc(output_buffer_size);

    int driver;
    if (libao_driver) {
        // if a libao driver is specified on the command line, use that
        driver = ao_driver_id(libao_driver);
        if (driver == -1) {
			debugp( DEBUGP_DEFAULT, 0, "Could not find requested ao driver" );
			kill( getpid(), SIGINT );
        }
    } else {
        // otherwise choose the default
        driver = ao_default_driver_id();
    }

    ao_sample_format fmt;
    memset(&fmt, 0, sizeof(fmt));
	
    fmt.bits = 16;
    fmt.rate = sess->sample_rate;
    fmt.channels = NUM_CHANNELS;
    fmt.byte_format = AO_FMT_NATIVE;
	
    ao_option *ao_opts = NULL;
    if(libao_deviceid) {
        ao_append_option(&ao_opts, "id", libao_deviceid);
    } else if(libao_devicename){
        ao_append_option(&ao_opts, "dev", libao_devicename);
        // Old libao versions (for example, 0.8.8) only support
        // "dsp" instead of "dev".
        ao_append_option(&ao_opts, "dsp", libao_devicename);
    }

    dev = ao_open_live(driver, &fmt, ao_opts);

    if (dev == NULL) {
		debugp( DEBUGP_DEFAULT, 0, "Could not open ao device (%d)", errno);
		kill( getpid(), SIGINT );
    }

	if(pthread_create( &ao_thread, NULL, ao_thread_func, NULL ))
	{
		debugp( DEBUGP_DEFAULT, 0, "Could not start ao_thread\n" );
		kill( getpid(), SIGINT );
	}

    return;
}

void play( void *output_samples, uint32_t num_bytes )
{
	ao_play( dev, output_samples, num_bytes );
	return;

	pthread_mutex_lock( &bufmutex );

	memcpy( output_buffer, output_samples, num_bytes );
	bytes_in_buffer = num_bytes;
	buffer_ready = 1;

	// Send signal
	debugp( DEBUGP_DEFAULT, 7, "signaling\n" );
	pthread_cond_signal( &buftrig );
	pthread_mutex_unlock( &bufmutex );
	
	pthread_mutex_lock( &bufmutex );
	pthread_cond_wait( &buftrig, &bufmutex );
	pthread_mutex_unlock( &bufmutex );
	return;
}

void *ao_thread_func( void *arg )
{
	// Wait for signal 
	while(1)
	{
		pthread_mutex_lock( &bufmutex );
		pthread_cond_wait( &buftrig, &bufmutex );
		
		if( buffer_ready )
		{
			// Send the buffer to ao
			ao_play( dev, output_buffer, bytes_in_buffer );
			debugp( DEBUGP_DEFAULT, 7, "playing\n" );
			memset( output_buffer, 0, bytes_in_buffer );
			buffer_ready = 0;
		}
		else
		{
			debugp( DEBUGP_DEFAULT, 7, "notready\n" );
		}
		
		pthread_cond_signal( &buftrig );
		pthread_mutex_unlock( &bufmutex );
	}
	pthread_mutex_unlock( &bufmutex );
	pthread_exit(NULL);
}


#endif
