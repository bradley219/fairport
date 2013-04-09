#include "debugp.h"

static int __debug_facility = DEBUGP_STDERR;
static int __global_debug_level = 0;

static pthread_mutex_t debugp_mutex = PTHREAD_MUTEX_INITIALIZER;

static int global_debugp_type = 0;

debugp_names_t debugp_names[] =
{
	{ DEBUGP_DEFAULT, "default" },
	{ DEBUGP_TIMING_PACKETS, "udptiming" },
	{ DEBUGP_CONTROL_PACKETS, "udpcontrol" },
	{ DEBUGP_AUDIO_PACKETS, "udpaudio" },
	{ DEBUGP_AUDIO_OUTPUT, "audio" },
	{ DEBUGP_AUDIO_MGMT, "audiomgmt" },
	{ DEBUGP_AUDIO_BUFFER_PRINT, "bufferprint" },
	{ DEBUGP_TCP, "tcp" },
};
int debugp_names_count = sizeof(debugp_names)/sizeof(debugp_names_t);

void setup_debugp_syslog( char *ident )
{

	/* Init syslog */
	openlog( ident, LOG_PID, LOG_DAEMON );

	return;
}

void change_debug_facility( int new_facility )
{
	__debug_facility = new_facility;


	return;
}

void set_debug_level( int level )
{
	__global_debug_level = level;
	return;
}
void change_debug_level_by( int by )
{
	__global_debug_level += by;
	return;
}
int get_debug_level(void)
{
	return __global_debug_level;
}

int set_debug_type( int type )
{
	global_debugp_type = type;
	return 0;
}
int add_debug_type( debugp_t type )
{
	global_debugp_type |= (1<<type);
	return 0;
}

int debugp( debugp_t type, int debug_level, char* format_string, ... )
{
	int length = 0;

	pthread_mutex_lock( &debugp_mutex );
	
	if( debug_level <= __global_debug_level ) // global flag_verbose
	{

		if( global_debugp_type & (1<<type) )
		{
			va_list arg_ptr;
			va_start( arg_ptr, format_string );

			if( __debug_facility == DEBUGP_STDERR )
			{
				length = vfprintf( stderr, format_string, arg_ptr );
			}
			else if( __debug_facility == DEBUGP_SYSLOG )
			{
				vsyslog( LOG_DEBUG, format_string, arg_ptr );
			}

			va_end( arg_ptr );
		}
	}
	pthread_mutex_unlock( &debugp_mutex );

	return length;
}

void debugp_cleanup(void)
{
	closelog();
	return;
}
