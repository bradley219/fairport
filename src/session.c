#ifndef _FAIRPORT_SESSION_SOURCE_
#define _FAIRPORT_SESSION_SOURCE_
#include "session.h"

static int num_sessions = 0;
static session_t **sessions = NULL;

pthread_mutex_t thread_search_mutex = PTHREAD_MUTEX_INITIALIZER;

static int add_session( session_t *s );

session_t *create_session( int timeout )
{
	// Allocate space for the new session
	session_t *session;
	if( ( session = malloc(sizeof(session_t)) ) != NULL )
	{
		memset( session, 0, sizeof(session_t) );
		// Create a unique session id
		do {
			session->id = rand() * rand();
		} while( (find_session(session->id)) != NULL );

		// Session init values
		
		clock_gettime( CLOCK_REALTIME, &session->expire );
		session->expire.tv_sec += timeout;

		session->num_channels = 2;
		session->buffer_frames = BUFFER_FRAMES;
		session->buffer_lead_frames = BUFFER_LEAD_FRAMES;

		session->fix_volume = 2153; // default to a very low volume

		session->bf_playback_rate = 1.0;


		// pthread vars
		session->thread = 0;
		pthread_mutex_init(&session->mutex,NULL);
		pthread_mutex_init(&session->packet_sig_mutex,NULL);
		pthread_cond_init(&session->packet_sig_cond,NULL);
		
		add_session(session);
	}
	return session;
}

int add_session( session_t *s )
{
	int retval = -1;
	if( ( sessions = realloc( sessions, sizeof(session_t*) * (num_sessions+1) ) ) != NULL )
	{
		retval = 0;
		sessions[num_sessions] = s;
		num_sessions++;

	}
	return retval;
}
session_t *get_first_session(void)
{
	session_t *s = NULL;
	if(num_sessions)
		s = sessions[0];
	return s;
}

int close_session( session_t *session )
{
	int retval = -1;
	for( int i=0; i < num_sessions; i++ )
	{
		// move subsequent sessions up one
		if( sessions[i] == session )
		{
			for( int j=i; j < (num_sessions-1); j++ )
			{
				sessions[j] = sessions[j+1];
			}
			num_sessions--;
			sessions = realloc( sessions, sizeof(session_t*) * (num_sessions));
			retval = 0;
			break;
		}
	}
	// free the session's stuff
	free( session->decoder_info );
	free( session );
	return retval;
}
session_t *find_session_by_str( char *session_id )
{
	pthread_mutex_lock( &thread_search_mutex );

	session_t *session = NULL;
	uint32_t id = 0;
	sscanf( session_id, "%08X", &id );
	for( int i=0; i < num_sessions; i++ )
	{
		if( sessions[i]->id == id )
		{
			session = sessions[i];
			break;
		}
	}
	
	pthread_mutex_unlock( &thread_search_mutex );
	return session;
};

session_t *find_session_by_audio_signature( uint32_t sig )
{
	pthread_mutex_lock( &thread_search_mutex );

	session_t *session = NULL;
	for( int i=0; i < num_sessions; i++ )
	{
		if( sessions[i]->audio_signature == sig ) // found it
		{
			session = sessions[i];
			break;
		}
	}
	if( session == NULL ) // if we didn't find a session, look for new sessions with blank signatures
	{
		for( int i=0; i < num_sessions; i++ )
		{
			if( sessions[i]->audio_signature == 0 ) // must be new
			{
				sessions[i]->audio_signature = sig;
				break;
			}
		}
	}
	
	pthread_mutex_unlock( &thread_search_mutex );
	return session;
};

session_t *find_session_by_control_signature( uint32_t sig )
{
	pthread_mutex_lock( &thread_search_mutex );

	session_t *session = NULL;
	for( int i=0; i < num_sessions; i++ )
	{
		if( sessions[i]->control_signature == sig ) // found it
		{
			session = sessions[i];
			break;
		}
	}
	if( session == NULL ) // if we didn't find a session, look for new sessions with blank signatures
	{
		for( int i=0; i < num_sessions; i++ )
		{
			if( sessions[i]->control_signature == 0 ) // must be new
			{
				sessions[i]->control_signature = sig;
				break;
			}
		}
	}
	
	pthread_mutex_unlock( &thread_search_mutex );
	return session;
};
session_t *find_session_by_host( struct sockaddr_storage *search )
{
	pthread_mutex_lock( &thread_search_mutex );

	int search_length = 0;
	unsigned char *search_address;
	short search_family = -1;

	// Determine IPv4 or IPv6 
	if( search->ss_family == AF_INET ) // IPv4
	{
		search_address = (unsigned char*)&(((struct sockaddr_in*)(search))->sin_addr);
		search_length = sizeof(unsigned long);
		search_family = AF_INET;
	}
	else if( search->ss_family == AF_INET6 ) // IPv6
	{
		search_address = (unsigned char*)&(((struct sockaddr_in6*)(search))->sin6_addr);
		search_length = 16;
		search_family = AF_INET6;
	}

	session_t *session = NULL;
	for( int i=0; i < num_sessions; i++ )
	{
		session_t *test_session = sessions[i];
		if( test_session->remote_host.ss_family == search_family )
		{
			int matched = 1;
			
			unsigned char *test_address = NULL;
			if( test_session->remote_host.ss_family == AF_INET )
			{
				test_address = (unsigned char*)&(((struct sockaddr_in*)&((test_session->remote_host)))->sin_addr);
			}
			else if( test_session->remote_host.ss_family == AF_INET6 )
			{
				test_address = (unsigned char*)&(((struct sockaddr_in6*)&((test_session->remote_host)))->sin6_addr);
			}

			unsigned char *ta = test_address;
			unsigned char *sa = search_address;
			for( int j = 0; j < search_length; j++ )
			{
				unsigned char tac = *ta++;
				unsigned char sac = *sa++;
				//debugp( DEBUGP_DEFAULT, 3, "tac = 0x%02x; sac = 0x%02x\n", tac, sac );
				if( tac != sac )
				{
					matched = 0;
					break;
				}
			}

			if( matched == 1 )
			{
				session = sessions[i];
				break;
			}
		}
	}
	
	pthread_mutex_unlock( &thread_search_mutex );
	return session;
};

session_t *find_session( uint32_t id )
{
	pthread_mutex_lock( &thread_search_mutex );

	session_t *session = NULL;
	for( int i=0; i < num_sessions; i++ )
	{
		if( sessions[i]->id == id )
		{
			session = sessions[i];
			break;
		}
	}
	
	pthread_mutex_unlock( &thread_search_mutex );
	return session;
};



/*
session_t *create_session2( int timeout )
{
	session_t *session;
	if( ( session = malloc(sizeof(session_t)) ) != NULL )
	{
		char ss[9];
		do {
			session->id = rand() * rand();
			sprintf( ss, "%08X", session->id );
		} while( (find_session(ss)) != NULL );

		// Session init values
		

		session->buffer_start_fill = START_FILL;
		session->ab_buffering = 1;
		session->ab_synced = 0;
		session->decoder_info = NULL;

		session->audio_buffer = malloc( sizeof(abuf_t) * BUFFER_FRAMES );

		session->remote_host = malloc( sizeof(struct sockaddr_storage) );

		clock_gettime( CLOCK_REALTIME, &session->expire );
		session->expire.tv_sec += timeout;
		session->teardown = 0;
		session->flush = 0;

		session->timing_port = 0;
		session->control_port= 0;
		session->server_port = 0;

		session->fix_volume = 2153; // default to a very low volume
		session->bf_playback_rate = 1.0;
		session->sock = 0;
		session->csock = 0;
		session->tsock = 0;
		session->ao_plays = 0;

		session->bf_est_drift = 0.0;
		session->bf_est_err = 0.0;

		// pthread vars
		session->hairthread = malloc(sizeof(pthread_t));

		session->cc_mutex = malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(session->cc_mutex,NULL);

		session->cc_param_changed_mutex = malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(session->cc_param_changed_mutex,NULL);

		session->cc_param_changed = malloc(sizeof(pthread_cond_t));
		pthread_cond_init(session->cc_param_changed,NULL);
		
		session->ht_ready_mutex = malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(session->ht_ready_mutex,NULL);

		session->ht_ready = malloc(sizeof(pthread_cond_t));
		pthread_cond_init(session->ht_ready,NULL);
		
		session->vol_mutex = malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(session->vol_mutex,NULL);

		session->ab_mutex = malloc(sizeof(pthread_mutex_t));
		pthread_mutex_init(session->ab_mutex,NULL);
		
		session->ab_buffer_ready = malloc(sizeof(pthread_cond_t));
		pthread_cond_init(session->ab_buffer_ready,NULL);

		add_session(session);
	}
	return session;
}
*/


#endif
