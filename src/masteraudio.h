#ifndef _MASTERAUDIO_H_
#define _MASTERAUDIO_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <assert.h>

#include <pthread.h>
#include "debugp.h"

#include "constants.h"
#include "session.h"
#include "alac.h"
#include "fairport.h"


int init_audio(void);
extern int master_buffer_size;

extern char *libao_driver;
extern char *libao_devicename;
extern char *libao_deviceid;

uint32_t get_master_rtp_time(void);
char *write_to_master_buffer( char *buffer, int num_frames, char *bptr );


#endif
