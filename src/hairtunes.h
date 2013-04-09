#ifndef _HAIRTUNES_H_
#define _HAIRTUNES_H_

#define BUFFERING_STYLE 1
#define BUFFER_TIMEOUT 60

#undef AF_INET6

typedef struct audio_buffer_entry {   // decoded audio packets
    int ready;
    signed short *data;
} abuf_t;
typedef unsigned short seq_t;
typedef struct {
    double hist[2];
    double a[2];
    double b[3];
} biquad_t;

void *hairtunes_thread( void *arg );

// default buffer size
// needs to be a power of 2 because of the way BUFIDX(seqno) works
#define BUFFER_FRAMES  512
#define START_FILL    282
#define MAX_PACKET      2048
#define NUM_CHANNELS 2

#define VU_METER_ENABLE 0
#define SCREEN_WIDTH 170

#endif 
