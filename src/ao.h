#ifndef _FAIRPORT_AO_H_
#define _FAIRPORT_AO_H_
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <pthread.h>
#include <math.h>

#include <ao/ao.h>
#include "session.h"
#include "debugp.h"

void init_ao( session_t *sess );
void play( void *output_samples, uint32_t num_bytes );

#endif
