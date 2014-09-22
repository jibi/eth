/*
 * Copyright (C) 2014 jibi <jibi@paranoici.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _ETH_EXOTCP_TCP_H
#define _ETH_EXOTCP_TCP_H

typedef struct tcp_conn_s tcp_conn_t;
typedef struct http_response_s http_response_t;

#include <stdio.h>
#include <stdint.h>

#include <eth/netmap.h>
#include <eth/exotcp.h>
#include <eth/http11.h>

#include <glib.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

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

typedef struct tcp_mss_sack_win_ts_opts_s {
	tcp_mss_opt_t       mss;
	tcp_sack_perm_opt_t sack_perm;
	tcp_win_scale_opt_t win_scale;
	tcp_ts_opt_t        ts;
	tcp_eol_opt_t       eol;
} __attribute__ ((packed)) tcp_mss_sack_win_ts_opts_t;

typedef tcp_mss_sack_win_ts_opts_t tcp_syn_ack_opts_t;

typedef struct tcp_ts_opts_s {
	tcp_ts_opt_t  ts;
	tcp_nop_opt_t nop;
	tcp_eol_opt_t eol;
} __attribute__ ((packed)) tcp_ts_opts_t;

typedef tcp_ts_opts_t  tcp_ack_opts_t;
typedef tcp_ts_opts_t tcp_data_opts_t;
typedef tcp_ts_opts_t tcp_fin_ack_opts_t;

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

#define TCP_DATA_PACKET_PAYLOAD(x) (x + sizeof(eth_hdr_t) + sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + sizeof(tcp_data_opts_t))
#define TCP_WINDOW_SIZE 0x4000

/*
 * from RFC 6691:
 *
 *  When calculating the value to put in the TCP MSS option, the MTU
 *  value SHOULD be decreased by only the size of the fixed IP and TCP
 *  headers and SHOULD NOT be decreased to account for any possible IP or
 *  TCP options; conversely, the sender MUST reduce the TCP data length
 *  to account for any IP or TCP options that it is including in the
 *  packets that it sends.  The rest of this document just expounds on
 *  that statement, and the goal is to avoid IP-level fragmentation of
 *  TCP packets.
 *
 * So, assuming we are on an ethernet network, we set MSS to:
 * ethernet MTU - ip header size - tcp header size,
 * without counting options
 */
#define TCP_MSS       (ETH_MTU - sizeof(ip_hdr_t) - sizeof(tcp_hdr_t))
#define TCP_WIN_SCALE 0

typedef enum tcp_state_e {
	SYN_RCVD,
	ESTABLISHED,
	FIN_SENT
} tcp_state_t;

/* assuming the server will use only one address and one port, it is ok
 * to use only src address and port as the TCP connection key */

typedef struct tcp_conn_key_s {
	uint32_t src_addr;
	uint16_t src_port;
} tcp_conn_key_t;

typedef struct tcp_conn_s {
	tcp_conn_key_t *key;
	uint8_t  src_mac[6];

	uint32_t last_recv_byte;
	uint32_t last_sent_byte;
	uint32_t last_ackd_byte;

	tcp_state_t state;
	uint32_t last_clock;

	int effective_window;

	uint16_t mss;
	uint8_t  win_scale;
	uint8_t  sack_perm;
	uint32_t ts;
	uint32_t echo_ts;

	/*
	 * data_buffer is the TCP "system" buffer, where we receive data.
	 *
	 * Theorically we sould need another buffer (which would be the
	 * "application" buffer) where the application copies data received from
	 * the socket.
	 *
	 * Practically we use only one buffer shared between the TCP stack and
	 * the app. So no need to copy data.
	 */

	uint8_t data_buffer[TCP_WINDOW_SIZE];
	size_t  data_len;

	http_response_t *http_response;
} tcp_conn_t;

extern GHashTable *tcb_hash;

void init_tcp();
void process_tcp(packet_t *p);
int tcp_conn_has_data_to_send(tcp_conn_t *conn);
void tcp_conn_send_data(tcp_conn_t *conn);

#endif

