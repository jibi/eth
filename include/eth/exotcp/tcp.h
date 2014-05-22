#include <stdint.h>

typedef struct tcp_hdr_s {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq;
	uint32_t ack;
	uint8_t  res:4;
	uint8_t  data_offset:4;
	uint8_t  flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urg_pointer;
} __attribute__ ((packed)) tcp_hdr_t;

# define TCP_FLAG_FIN  0x01
# define TCP_FLAG_SYN  0x02
# define TCP_FLAG_RST  0x04
# define TCP_FLAG_PUSH 0x08
# define TCP_FLAG_ACK  0x10
# define TCP_FLAG_URG  0x20

void process_tcp(char *packet_buf);

typedef enum tcp_state_e {
	SYN_RCVD,
	ESTABLISHED
} tcp_state_t;

typedef struct tcp_conn_key_s {
	uint32_t src_addr;
	uint16_t src_port;
} tcp_conn_key_t;

typedef struct tcp_conn_s {
	tcp_conn_key_t *key;
	int ack;
	int seq;
	tcp_state_t state;

	uint16_t mss;
	uint8_t  win_scaling;
	uint8_t  sack_permitted;
	uint32_t timestamp;
	uint32_t echo_timestamp;
} tcp_conn_t;

