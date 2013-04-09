#ifndef _FAIRPORT_SESSION_SOURCE_
#define _FAIRPORT_SESSION_SOURCE_
#include "session.h"

static int num_sessions = 0;
static struct session **sessions = NULL;

static int add_session( struct session *s )
{
	int retval = -1;
	if( ( sessions = realloc( sessions, sizeof(struct session*) * (num_sessions+1) ) ) != NULL )
	{
		retval = 0;
		sessions[num_sessions] = s;
		num_sessions++;

		if( num_sessions > 1 )
		{
			sessions[num_sessions-2]->next = s;
		}
	}
	return retval;
}
struct session *get_first_session(void)
{
	struct session *s = NULL;
	if(num_sessions)
		s = sessions[0];
	return s;
}

int close_session( struct session *session )
{
	int retval = -1;
	for( int i=0; i < num_sessions; i++ )
	{
		// free the session's stuff
		free( session->rtp_client );
		free( session->audio_buffer );
		free( session->decoder_info );


		// move subsequent sessions up one
		if( sessions[i] == session )
		{
			for( int j=i; j < (num_sessions-1); j++ )
			{
				sessions[j] = sessions[j+1];
			}
			num_sessions--;
			sessions = realloc( sessions, sizeof(struct session*) * (num_sessions));
			retval = 0;
			break;
		}
	}
	for( int i=0; i < num_sessions; i++ )
	{
		if( i == (num_sessions-1) ) // last session in list
		{
			sessions[i]->next = NULL;
		}
		else
		{
			sessions[i]->next = sessions[i+1];
		}
	}
	return retval;
}
struct session *find_session( char *session_id )
{
	struct session *session = NULL;
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
	return session;
};
struct session *create_session( int timeout )
{
	struct session *session;
	if( ( session = malloc(sizeof(struct session)) ) != NULL )
	{
		char ss[9];
		do {
			session->id = rand() * rand();
			sprintf( ss, "%08X", session->id );
		} while( (find_session(ss)) != NULL );

		// Session init values
		
		session->next = NULL;
		//session->dev = NULL;

		session->buffer_start_fill = START_FILL;
		session->ab_buffering = 1;
		session->ab_synced = 0;
		session->decoder_info = NULL;

		session->audio_buffer = malloc( sizeof(abuf_t) * BUFFER_FRAMES );

		session->rtp_client = malloc( sizeof(struct sockaddr_storage) );

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


#endif
