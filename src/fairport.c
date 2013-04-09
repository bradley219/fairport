#ifndef _FAIRPORT_SOURCE_
#define _FAIRPORT_SOURCE_
#include "fairport.h"

/** 
 * Functions
 */
void parse_args( int argc, char *argv[] );
int create_name( char *in_name, char *out_name );
int publish_service( char *name, char *port );
int publish_service2( char *name, char *port, char *host );
void chld_handler( int signo );
void sighandler( int signo );

/**
 * Globals
 */
static char *tcp_port = "5000";
static char *mdns_publish_service = "/usr/bin/avahi-publish-service";

static pid_t mdns_pid = 0;

static char *private_key_file = "/etc/fairport/private.key";
char *apname = "default";
int going_down = 0;
char *start_task = NULL;
char *end_task = NULL;

// screen size
volatile struct winsize window_size;

void winch_handler( int sig )
{
	int wd = open( "/dev/tty", O_RDWR );

	int i;
	if( ( i = ioctl( wd, TIOCGWINSZ, &window_size ) ) )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: ioctl() returned %d\n", i );
		kill( getpid(), SIGINT );
	}
	return;
}
int set_debug_type_by_name( char *name )
{
	int retval = 1;
	for( int i=0; i < debugp_names_count; i++ )
	{
		if( strcasecmp( name, debugp_names[i].name ) == 0 )
		{
			retval = 0;
			debugp( DEBUGP_DEFAULT, 0, "Adding debugging type `%s'\n", name );
			add_debug_type( debugp_names[i].type );
			break;
		}
	}
	if( retval )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: could not find debugging type `%s'\n", name );
	}
	return;
}

int pthread_cond_reltimedwait( pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *reltime, clockid_t clock_id )
{
	struct timespec abs;
	struct timespec now;
	clock_gettime( clock_id, &now );

	abs.tv_nsec = now.tv_nsec + reltime->tv_nsec;
	abs.tv_sec = now.tv_sec + reltime->tv_sec;
	if( abs.tv_nsec > 1000000000 )
	{
		abs.tv_nsec -= 1000000000;
		abs.tv_sec += 1;
	}
	
	return pthread_cond_timedwait( cond, mutex, &abs );
}

int main( int argc, char *argv[] ) 
{
	int retval = 0;

	int len = 0xffff;
	assert( len <= MAX_PACKET );
	
	set_debug_type(0);
	add_debug_type( DEBUGP_DEFAULT );

	parse_args( argc, argv );

	signal( SIGCHLD, chld_handler );
	signal( SIGINT, sighandler );
	signal( SIGSEGV, sighandler );
	signal( SIGBUS, sighandler );
	signal( SIGWINCH, winch_handler );

	winch_handler(SIGWINCH);

	pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

	while(1)
	{
		struct timespec delta = { .tv_sec = 0, .tv_nsec = 600000000 };
		
		pthread_mutex_lock( &mutex );
		debugp( DEBUGP_DEFAULT, 0, "waiting..." );
		int wait = pthread_cond_reltimedwait( &cond, &mutex, &delta, CLOCK_REALTIME );
		pthread_mutex_unlock( &mutex );
		
		debugp( DEBUGP_DEFAULT, 0, "done; returned %d\n", wait );
		sleep(1);
	}



	load_private_key(private_key_file);

	if( ( mdns_pid = publish_service( apname, tcp_port ) ) <= 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: publish_service()\n" );
		kill( getpid(), SIGINT );
	}
	if( init_audio() )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: init_audio()\n" );
		kill( getpid(), SIGINT );
	}
	if( init_udp_listeners() )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: init_udp_listeners()\n" );
		kill( getpid(), SIGINT );
	}
	if(create_listening_thread(tcp_port))
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: create_listening_thread()\n" );
		kill( getpid(), SIGINT );
	}
	while(1)
	{
		//debugp( DEBUGP_DEFAULT, 0, "Waiting for child %d\n", mdns_pid );
		sleep(10);
	}

	return retval;
}
int publish_service( char *name, char *port )
{
	char *service_name = malloc( sizeof(char) * (strlen(name) + 14) );
	if(create_name( name, service_name ))
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: create_name\n" );
		kill( getpid(), SIGINT );
	}
	
	int child_pid = fork();
	if( child_pid < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: fork()\n" );
		return -1;
	}
	else if( child_pid == 0 )
	{
		debugp( DEBUGP_DEFAULT, 6, "Child process running\n" );
		char *args[] = {
			mdns_publish_service,
			"--service",
			service_name,
			"_raop._tcp",
			port,
			"txtvers=1",
			"vn=3",
			"pw=false",
			"sr=44100",
			"ss=16",
			"ch=2",
			"cn=0,1",
			"et=0,1",
			"ek=1",
			"sv=false",
			"sm=false",
			"tp=UDP",
			NULL
		};
		if( execvp( mdns_publish_service, args ) != 0 )
		{
			debugp( DEBUGP_DEFAULT, 0, "Error: execvp\n" );
			kill( getpid(), SIGINT );
		}
		debugp( DEBUGP_DEFAULT, 0, "Unreachable\n" );
	}
	else
	{
		debugp( DEBUGP_DEFAULT, 6, "Forked child pid %d\n", child_pid );
		free(service_name);
	}
	return child_pid;
}
int publish_service2( char *name, char *port, char *host )
{
	char *service_name = malloc( sizeof(char) * (strlen(name) + 14) );
	if(create_name( name, service_name ))
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: create_name\n" );
		kill( getpid(), SIGINT );
	}
	
	int child_pid = fork();
	if( child_pid < 0 )
	{
		debugp( DEBUGP_DEFAULT, 0, "Error: fork()\n" );
		return -1;
	}
	else if( child_pid == 0 )
	{
		debugp( DEBUGP_DEFAULT, 6, "Child process running\n" );
		char *args[] = {
			mdns_publish_service,
			"--host",
			host,
			"--service",
			service_name,
			"_raop._tcp",
			port,
			"txtvers=1",
			"vn=3",
			"pw=false",
			"sr=44100",
			"ss=16",
			"ch=2",
			"cn=0,1",
			"et=0,1",
			"ek=1",
			"sv=false",
			"sm=false",
			"tp=UDP",
			NULL
		};
		if( execvp( mdns_publish_service, args ) != 0 )
		{
			debugp( DEBUGP_DEFAULT, 0, "Error: execvp\n" );
			kill( getpid(), SIGINT );
		}
		debugp( DEBUGP_DEFAULT, 0, "Unreachable\n" );
	}
	else
	{
		debugp( DEBUGP_DEFAULT, 6, "Forked child pid %d\n", child_pid );
		free(service_name);
	}
	return child_pid;
}
void sighandler( int signo )
{
	debugp( DEBUGP_DEFAULT, 2, "Caught signal: %d\n", signo );
	going_down = 1;

	siginfo_t siginfo;
	if(waitid( 
		P_PID, 
		mdns_pid, 
		&siginfo, 
		WEXITED | WSTOPPED | WCONTINUED | WNOHANG )==0)
	{
		going_down = 1;
		//kill( mdns_pid, SIGTERM );
	}

	exit(-1);
	return;
}
void chld_handler( int signo )
{
	if( signo==SIGCHLD )
	{
		debugp( DEBUGP_DEFAULT, 4, "PID %d received SIGCHLD\n", getpid() );
		
		siginfo_t siginfo;
		
		if(waitid( P_ALL, 0, &siginfo, WEXITED | WSTOPPED | WCONTINUED )==0)
		{
			debugp( DEBUGP_DEFAULT, 4, "   child pid: %d ", siginfo.si_pid );
			switch(siginfo.si_code)
			{
				case CLD_EXITED:
					debugp( DEBUGP_DEFAULT, 4, "exited " );
					break;
				case CLD_KILLED:
					debugp( DEBUGP_DEFAULT, 4, "killed " );
					break;
				case CLD_DUMPED:
					debugp( DEBUGP_DEFAULT, 4, "killed and dumped " );
					break;
				case CLD_STOPPED:
					debugp( DEBUGP_DEFAULT, 4, "stopped " );
					break;
				case CLD_CONTINUED:
					debugp( DEBUGP_DEFAULT, 4, "continued " );
					break;
				case CLD_TRAPPED:
					debugp( DEBUGP_DEFAULT, 4, "trapped " );
					break;
			}
			if(siginfo.si_code == CLD_EXITED)
				debugp( DEBUGP_DEFAULT, 4, "with status %d\n", siginfo.si_status );
			else
				debugp( DEBUGP_DEFAULT, 4, "by signal %d\n", siginfo.si_status );

			if( (mdns_pid == siginfo.si_pid) && !going_down )
			{
				debugp( DEBUGP_DEFAULT, 3, "mdns publisher killed. Respawning...\n" );
				if( publish_service( apname, tcp_port ) )
				{
					debugp( DEBUGP_DEFAULT, 0, "Error: publish_service()\n" );
					exit(-1);
				}
			}
		}
	}
	fflush(stderr);
	return;
}
int create_name( char *in_name, char *out_name )
{
	/* The service name is in the format:
	 * [hash]@[name]
	 * where [hash] is the first 6 bytes of the md5 sum 
	 * of [name] in uppercase hexadecimal format */
	unsigned char md5sum[16];
	char buf[3];

	if( MD5( (const unsigned char*)in_name, strlen(in_name), md5sum ) == NULL )
		return -1;

	out_name[0] = '\0';
	for(int i=0; i < 6; i++)
	{
		sprintf( buf, "%02X", md5sum[i] );
		strcat(out_name,buf);
	}
	strcat(out_name,"@");
	strcat(out_name,in_name);
	return 0;
}
void parse_args( int argc, char *argv[] )
{

	struct option long_options[] =
	{
		{ "end-task", optional_argument, NULL, 'e' },
		{ "start-task", optional_argument, NULL, 's' },
		{ "verbose", optional_argument, NULL, 'v' },
		{ "apname", required_argument, NULL, 'a' },
		{ "tcp-port", required_argument, NULL, 'p' },
		{ "mdns-publish-service", required_argument, NULL, 'm' },
		{ 0, 0, 0, 0 }
	};
	int long_options_index;

	int c;
	while( ( c = getopt_long( argc, argv, "d:s:e:m:a:v", long_options, &long_options_index )) != -1 ) 
	{
		switch(c) 
		{
			case 0: /* Long options with no short equivalent */
				break;
			case 's':
				start_task = optarg;
				break;
			case 'e':
				end_task = optarg;
				break;
			case 'm':
				mdns_publish_service = optarg;
				break;
			case 'p':
				tcp_port = optarg;
				break;
			case 'a':
				apname = optarg;
				break;
			case 'v':
				change_debug_level_by(1);
				break;
			case 'd':
				set_debug_type_by_name(optarg);
				break;
			default:
				break;
		}
	}

	return;
}

#endif
