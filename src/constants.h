#ifndef _CONSTANTS_H_
#define _CONSTANTS_H_

/* RTP header bits */
#define RTP_HEADER_A_EXTENSION 0x10
#define RTP_HEADER_A_SOURCE 0x0f

#define RTP_HEADER_B_PAYLOAD_TYPE 0x7f
#define RTP_HEADER_B_MARKER 0x80

#define PAYLOAD_TYPE_TIMING_REQUEST 0x52
#define PAYLOAD_TYPE_TIMING_RESPONSE 0x53
#define PAYLOAD_TYPE_SYNC 0x54
#define PAYLOAD_TYPE_RANGE_RESEND 0x55
#define PAYLOAD_TYPE_RESENT_AUDIO 0x56
#define PAYLOAD_TYPE_AUDIO 0x60

/* Constants */
#define FRAMES_PER_PACKET 			352 		//	Audio frames per packet
#define SHORTS_PER_PACKET 			2 			// * FRAMES_PER_PACKET 	Shorts per packet
#define TIMESTAMPS_PER_SECOND 	44100 	// Timestamps per second
#define TIMESYNC_INTERVAL 			44100 	// Once per second
#define PACKET_BACKLOG 				1000 		// Packet resend buffer size
#define TIME_PER_PACKET 			((double)FRAMES_PER_PACKET / (double)44100)  // Milliseconds

/* Audio */
#define OUTFRAME_BYTES (4*(sess->frame_size+3))

#define MAX_PACKET 2048

#define BUFFER_FRAMES 230
#define BUFFER_LEAD_FRAMES 60
#define BUFFER_FLUSHOUT_SIZE (BUFFER_FRAMES-BUFFER_LEAD_FRAMES)

#endif
