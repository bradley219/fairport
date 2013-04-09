#ifndef _FAIRPORT_H_
#define _FAIRPORT_H_

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <getopt.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <pthread.h>
#include "debugp.h"

#include <openssl/md5.h>

#include "../config.h"
#include "control.h"
#include "session.h"
#include "audio.h"
#include "masteraudio.h"


/** 
 * Macros
 */
#define LONGOPT( OPTNAME ) ( strcmp( long_options[long_options_index].name, OPTNAME ) == 0 )

extern volatile struct winsize window_size;
int pthread_cond_reltimedwait( pthread_cond_t *cond, pthread_mutex_t *mutex, const struct timespec *reltime, clockid_t clock_id );

#endif
