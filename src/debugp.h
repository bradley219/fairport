#ifndef _DEBUGP_H_
#define _DEBUGP_H_

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <pthread.h>

#define DEBUGP_STDERR 1
#define DEBUGP_SYSLOG 2

typedef enum {
	DEBUGP_DEFAULT,
	DEBUGP_TIMING_PACKETS,
	DEBUGP_CONTROL_PACKETS,
	DEBUGP_AUDIO_PACKETS,
	DEBUGP_AUDIO_OUTPUT,
	DEBUGP_AUDIO_MGMT,
	DEBUGP_AUDIO_BUFFER_PRINT,
	DEBUGP_TCP,
} debugp_t;

typedef struct {
	debugp_t type;
	char *name;
} debugp_names_t;

extern debugp_names_t debugp_names[];
extern int debugp_names_count;

int debugp( debugp_t type, int debug_level, char* format_string, ... );

void change_debug_level_by( int by );

void set_debug_level( int level );

int get_debug_level(void);
int add_debug_type( debugp_t type );
int set_debug_type( int type );

void change_debug_facility( int new_facility );

void setup_debugp_syslog( char *ident );

void debugp_cleanup(void);
#endif
