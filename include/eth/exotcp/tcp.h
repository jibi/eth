#include <stdint.h>

#include <eth/exotcp.h>

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

typedef struct tcp_pseudo_header_s {
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t  reserved;
	uint8_t  proto;
	uint16_t length;
} __attribute__ ((packed)) tcp_pseudo_header_t;

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

typedef struct tcp_mss_opt_s {
	uint8_t  code;
	uint8_t  len;
	uint16_t size;
} __attribute__ ((packed)) tcp_mss_opt_t;

typedef struct tcp_sack_perm_opt_t {
	uint8_t  code;
	uint8_t  len;
} __attribute__ ((packed)) tcp_sack_perm_opt_t;

typedef uint8_t tcp_nop_opt_t;
typedef uint8_t tcp_eol_opt_t;

typedef struct tcp_ts_opt_s {
	uint8_t  code;
	uint8_t  len;
	uint32_t ts;
	uint32_t echo;
} __attribute__ ((packed)) tcp_ts_opt_t;

typedef struct tcp_win_scale_opt_s {
	uint8_t code;
	uint8_t len;
	uint8_t shift;
} __attribute__ ((packed)) tcp_win_scale_opt_t;

typedef struct tcp_syn_ack_opts_s {
	tcp_mss_opt_t       mss;
	tcp_sack_perm_opt_t sack_perm;
	tcp_win_scale_opt_t win_scale;
	tcp_ts_opt_t        ts;
	tcp_eol_opt_t       eol;
} __attribute__ ((packed)) tcp_syn_ack_opts_t;

typedef struct tcp_ack_opts_s {
	tcp_ts_opt_t  ts;
	tcp_nop_opt_t nop;
	tcp_eol_opt_t eol;
} __attribute__ ((packed)) tcp_ack_opts_t;

#define TCP_OPT_EOL_CODE       0x0
#define TCP_OPT_NOP_CODE       0x1
#define TCP_OPT_MSS_CODE       0x2
#define TCP_OPT_WIN_SCALE_CODE 0x3
#define TCP_OPT_SACK_PERM_CODE 0x4
#define TCP_OPT_SACK_CODE      0x5
#define TCP_OPT_TS_CODE        0x8

#define TCP_OPT_MSS_LEN       4
#define TCP_OPT_WIN_SCALE_LEN 3
#define TCP_OPT_SACK_PERM_LEN 2
//#define TCP_OPT_SACK_LEN
#define TCP_OPT_TS_LEN        10

void process_tcp(packet_t *p);

typedef enum tcp_state_e {
	SYN_RCVD,
	ESTABLISHED
} tcp_state_t;

/* assuming the server will use only one address and one port, it is ok
 * to use only src address and port as the TCP connection key */

typedef struct tcp_conn_key_s {
	uint32_t src_addr;
	uint16_t src_port;
} tcp_conn_key_t;

typedef struct tcp_conn_s {
	tcp_conn_key_t *key;
	uint32_t last_ack;
	uint32_t cur_seq;
	tcp_state_t state;
	uint32_t last_clock;

	uint16_t mss;
	uint8_t  win_scale;
	uint8_t  sack_perm;
	uint32_t ts;
	uint32_t echo_ts;
} tcp_conn_t;

void init_tcp();

#define TCP_WINDOW_SIZE 0x4000
#define TCP_MSS         1460
#define TCP_WIN_SCALE   0

