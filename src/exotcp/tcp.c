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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <sys/time.h>
#include <sys/uio.h>

#include <eth/log.h>

#include <eth/netmap.h>

#include <eth/exotcp.h>
#include <eth/exotcp/checksum.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>
#include <eth/exotcp/hash.h>

#include <eth/http11.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <glib.h>

/*
 * TCP control block hash table:
 * this table is used to keep track of all TCP connections.
 */
GHashTable *tcb_hash;

/*
 * prebuilt packet: sent in the phase 2 of the TCP three way handshake
 */
struct {
	eth_hdr_t          eth;
	ip_hdr_t           ip;
	tcp_hdr_t          tcp;
	tcp_syn_ack_opts_t opts;
} __attribute__ ((packed)) syn_ack_tcp_packet;

/*
 * prebuilt packet: sent when the server needs to ACK a client packet
 */
struct {
	eth_hdr_t      eth;
	ip_hdr_t       ip;
	tcp_hdr_t      tcp;
	tcp_ack_opts_t opts;
} __attribute__ ((packed)) ack_tcp_packet;

/*
 * prebuild packet: used to send data
 */
struct {
	eth_hdr_t       eth;
	ip_hdr_t        ip;
	tcp_hdr_t       tcp;
	tcp_data_opts_t opts;
} __attribute__ ((packed)) data_tcp_packet;

/*
 * prebuild packet: sent to ack a fin packet
 */
struct {
	eth_hdr_t          eth;
	ip_hdr_t           ip;
	tcp_hdr_t          tcp;
	tcp_fin_ack_opts_t opts;
} __attribute__ ((packed)) fin_ack_tcp_packet;

struct {
	eth_hdr_t          eth;
	ip_hdr_t           ip;
	tcp_hdr_t          tcp;
} __attribute__ ((packed)) rst_tcp_packet;

typedef struct tcp_send_data_ctx_s {
	nm_tx_desc_t http_hdr_last_tx_desc;
	uint16_t     slot_count;
	uint16_t     last_http_hdr_pl_len;

} tcp_send_data_ctx_t;

static inline void tcp_syn_ack_checksum();
static inline void tcp_ack_checksum();
static inline void tcp_data_checksum(char *data, uint16_t data_len);
static inline void tcp_fin_ack_checksum();
static inline void tcp_rst_checksum();

int
get_tcp_clock(tcp_conn_t *conn) {

	struct timeval tv;
	uint32_t       clock;

	gettimeofday(&tv, 0);

	clock = tv.tv_sec * 1000 + tv.tv_usec / 1000;

	if (clock <= conn->last_clock) {
		clock++;
		conn->last_clock = clock;
	}

	return clock;
}

void
init_tcp_packet_header(tcp_hdr_t *hdr, uint8_t opts_len, uint8_t flags) {

	hdr->src_port    = HTONS(listening_port);
	hdr->res         = 0;
	hdr->window      = HTONS(TCP_WINDOW_SIZE); /* TODO: comply to TCP window size */
	hdr->data_offset = (sizeof(tcp_hdr_t) + opts_len) / 4;
	hdr->flags       = flags;
}

void
setup_tcp_hdr(tcp_hdr_t *hdr, tcp_conn_t *conn) {

	hdr->dst_port = conn->key->src_port;
	hdr->ack      = htonl(conn->last_recv_byte + 1);
	hdr->seq      = htonl(conn->last_sent_byte);
}

void
init_syn_ack_tcp_packet() {

	init_eth_packet(&syn_ack_tcp_packet.eth);
	init_ip_packet(&syn_ack_tcp_packet.ip, sizeof(tcp_syn_ack_opts_t));
	init_tcp_packet_header(&syn_ack_tcp_packet.tcp, sizeof(tcp_syn_ack_opts_t), TCP_FLAG_SYN | TCP_FLAG_ACK);

	/* TODO: negotiate MSS */
	syn_ack_tcp_packet.opts = (tcp_syn_ack_opts_t) {
		.mss       = { .code = TCP_OPT_MSS_CODE,       .len = TCP_OPT_MSS_LEN },
		.sack_perm = { .code = TCP_OPT_SACK_PERM_CODE, .len = TCP_OPT_SACK_PERM_LEN},
		.win_scale = { .code = TCP_OPT_WIN_SCALE_CODE, .len = TCP_OPT_WIN_SCALE_LEN},
		.ts        = { .code = TCP_OPT_TS_CODE,        .len = TCP_OPT_TS_LEN},
		.eol       = TCP_OPT_EOL_CODE
	};
}

void
init_ack_tcp_packet() {

	init_eth_packet(&ack_tcp_packet.eth);
	init_ip_packet(&ack_tcp_packet.ip, sizeof(tcp_ack_opts_t));
	init_tcp_packet_header(&ack_tcp_packet.tcp, sizeof(tcp_ack_opts_t), TCP_FLAG_ACK);

	ack_tcp_packet.opts = (tcp_ack_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_data_tcp_packet() {

	init_eth_packet(&data_tcp_packet.eth);
	init_ip_packet(&data_tcp_packet.ip, sizeof(tcp_data_opts_t));
	init_tcp_packet_header(&data_tcp_packet.tcp, sizeof(tcp_ack_opts_t), TCP_FLAG_ACK | TCP_FLAG_PSH);

	data_tcp_packet.opts = (tcp_data_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_fin_ack_tcp_packet() {

	init_eth_packet(&fin_ack_tcp_packet.eth);
	init_ip_packet(&fin_ack_tcp_packet.ip, sizeof(tcp_fin_ack_opts_t));
	init_tcp_packet_header(&fin_ack_tcp_packet.tcp, sizeof(tcp_fin_ack_opts_t), TCP_FLAG_ACK | TCP_FLAG_FIN);

	fin_ack_tcp_packet.opts = (tcp_fin_ack_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_rst_tcp_packet() {

	init_eth_packet(&rst_tcp_packet.eth);
	init_ip_packet(&rst_tcp_packet.ip, 0);
	init_tcp_packet_header(&rst_tcp_packet.tcp, 0, TCP_FLAG_ACK | TCP_FLAG_RST);
}

void
init_tcp() {

	log_debug1("init_tcp");

	init_syn_ack_tcp_packet();
	init_ack_tcp_packet();
	init_data_tcp_packet();
	init_fin_ack_tcp_packet();
	init_rst_tcp_packet();

	tcb_hash = g_hash_table_new(hash_tcp_conn, cmp_tcp_conn);
}

void
parse_tcp_options(tcp_hdr_t *tcp_hdr, tcp_conn_t *conn) {

	char *cur_opt;
	cur_opt = ((char *) tcp_hdr) + sizeof(tcp_hdr_t);

	log_debug2("tcp options:");

	do {
		switch (*cur_opt) {
			case 0:
				log_debug2("\tend of options");
				break;
			case 1:
				log_debug2("\tno op");

				cur_opt++;
				break;
			case 2:
				log_debug2("\tmss: %d", (short) *(cur_opt + 2));
				conn->mss = (short) *(cur_opt + 2);

				cur_opt += 4;
				break;
			case 3:
				log_debug2("\twindow scaling");

				if (conn->state == SYN_RCVD) {
					/* win scaling is only valid during the
					 * 3wh*/
					conn->win_scale = *(cur_opt + 2);
				}

				cur_opt += 3;
				break;
			case 4:
				log_debug2("\tsack permitted");
				conn->sack_perm = 1;

				cur_opt += 2;
				break;
			case 5:
				log_debug2("\tsack");

				cur_opt += *(cur_opt + 1);
				break;
			case 8:
				log_debug2("\tts");
				conn->ts      = *((int *) (cur_opt + 2));
				conn->echo_ts = *((int *) (cur_opt + 6));

				cur_opt += 10;
				break;
			case 14:
				break;
			case 15:
				break;
			default:
				log_debug2("\tunknown tcp option!");
				cur_opt++;
		}
	} while(*cur_opt != 0 && cur_opt < (((char *) tcp_hdr) + tcp_hdr->data_offset * 4));
}

void
send_tcp_syn_ack(tcp_conn_t *conn) {

	log_debug1("send tcp SYN+ACK packet");

	setup_eth_hdr(&syn_ack_tcp_packet.eth, conn);
	setup_ip_hdr(&syn_ack_tcp_packet.ip, conn, 0);
	setup_tcp_hdr(&syn_ack_tcp_packet.tcp, conn);

	/* XXX */
	syn_ack_tcp_packet.opts.mss.size        = HTONS(TCP_MSS);
	syn_ack_tcp_packet.opts.ts.ts           = htonl(get_tcp_clock(conn));
	syn_ack_tcp_packet.opts.ts.echo         = conn->ts;
	syn_ack_tcp_packet.opts.win_scale.shift = TCP_WIN_SCALE;

	tcp_syn_ack_checksum();

	nm_send_packet(&syn_ack_tcp_packet, sizeof(syn_ack_tcp_packet));
}

void
send_tcp_ack(tcp_conn_t *conn) {

	log_debug1("send tcp ACK packet");

	setup_eth_hdr(&ack_tcp_packet.eth, conn);
	setup_ip_hdr(&ack_tcp_packet.ip, conn, 0);
	setup_tcp_hdr(&ack_tcp_packet.tcp, conn);

	ack_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	ack_tcp_packet.opts.ts.echo = conn->ts;

	tcp_ack_checksum();

	nm_send_packet(&ack_tcp_packet, sizeof(ack_tcp_packet));
}

void
send_tcp_data(tcp_conn_t *conn, char *packet_buf, char *data, uint16_t len) {

	log_debug1("send tcp data packet");

	setup_eth_hdr(&data_tcp_packet.eth, conn);
	setup_ip_hdr(&data_tcp_packet.ip, conn, len);
	setup_tcp_hdr(&data_tcp_packet.tcp, conn);

	data_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	data_tcp_packet.opts.ts.echo = conn->ts;

	tcp_data_checksum(data, len);

	memcpy(packet_buf, &data_tcp_packet, sizeof(data_tcp_packet));
}

void
send_tcp_fin_ack(tcp_conn_t *conn) {

	log_debug1("send tcp FIN+ACK packet");

	setup_eth_hdr(&fin_ack_tcp_packet.eth, conn);
	setup_ip_hdr(&fin_ack_tcp_packet.ip, conn, 0);
	setup_tcp_hdr(&fin_ack_tcp_packet.tcp, conn);

	fin_ack_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	fin_ack_tcp_packet.opts.ts.echo = conn->ts;

	tcp_fin_ack_checksum();

	nm_send_packet(&fin_ack_tcp_packet, sizeof(fin_ack_tcp_packet));
}

void
send_tcp_rst(packet_t *p, tcp_conn_t *conn) {

	log_debug1("send tcp RST packet");

	setup_eth_hdr(&rst_tcp_packet.eth, conn);
	setup_ip_hdr(&rst_tcp_packet.ip, conn, 0);
	setup_tcp_hdr(&rst_tcp_packet.tcp, conn);

	rst_tcp_packet.tcp.src_port = p->tcp_hdr->dst_port;

	tcp_rst_checksum();

	nm_send_packet(&rst_tcp_packet, sizeof(rst_tcp_packet));
}

void
send_tcp_rst_without_conn(packet_t *p) {

	//* build a fake conn to keep happy the functions that need a conn
	tcp_conn_t *conn    = malloc(sizeof(tcp_conn_t));
	tcp_conn_key_t *key = malloc(sizeof(tcp_conn_key_t));

	conn->last_recv_byte = p->tcp_hdr->seq;
	conn->last_sent_byte = 0;
	conn->key            = key;
	conn->key->src_addr  = p->ip_hdr->src_addr;

	memcpy(conn->src_mac, p->eth_hdr->mac_dst, sizeof(struct ether_addr));

	send_tcp_rst(p, conn);

	free(conn);
	free(key);
}

void
process_tcp_new_conn(packet_t *p) {

	struct timeval tv;

	if (unlikely(ntohs(p->tcp_hdr->dst_port) != listening_port)) {
		send_tcp_rst_without_conn(p);

		return;
	}

	tcp_conn_key_t *conn_key = malloc(sizeof(tcp_conn_key_t));
	tcp_conn_t     *conn     = malloc(sizeof(tcp_conn_t));

	gettimeofday(&tv, 0);

	conn->key           = conn_key;
	conn->key->src_port = p->tcp_hdr->src_port;
	conn->key->src_addr = p->ip_hdr->src_addr;
	memcpy(conn->src_mac, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	conn->last_recv_byte = ntohl(p->tcp_hdr->seq);
	conn->last_sent_byte = 1; /* XXX: we use 1 instead of  rand(); to avoid (temporarily) seq numbers wraparound */
	conn->state          = SYN_RCVD;
	conn->last_clock     = tv.tv_sec / 1000 + tv.tv_usec * 1000;

	conn->effective_window = 0;
	conn->win_scale        = 0;

	conn->data_len         = 0;
	conn->http_response    = NULL;

	log_debug1("recv tcp SYN packet");

	if (p->tcp_hdr->data_offset > 5) {
		parse_tcp_options(p->tcp_hdr, conn);
	}

	send_tcp_syn_ack(conn);

	g_hash_table_insert(tcb_hash, conn->key, conn);
}

tcp_conn_t *
get_tcp_conn(packet_t *p) {

	uint8_t *a = (uint8_t *) &p->ip_hdr->src_addr;
	log_debug2("get_tcp_conn: address %d.%d.%d.%d, port %d", a[0], a[1], a[2], a[3], p->tcp_hdr->src_port);

	tcp_conn_key_t key = {
		.src_port = p->tcp_hdr->src_port,
		.src_addr = p->ip_hdr->src_addr
	};

	return g_hash_table_lookup(tcb_hash, &key);
}

void
process_3wh_ack(packet_t *p, tcp_conn_t *conn) {
	/* TODO: check ack number */
	/* TODO: calc RTT */

	// with a SYN packet we need to ACK one byte.
	conn->last_sent_byte++;

	log_debug1("new connection established");
	conn->state = ESTABLISHED;
}

void
process_tcp_segment(packet_t *p, tcp_conn_t *conn) {

	char *payload;
	uint16_t  len = (ntohs(p->ip_hdr->total_len) - sizeof(ip_hdr_t) - (p->tcp_hdr->data_offset * 4));

	parse_tcp_options(p->tcp_hdr, conn);

	if (ntohl(p->tcp_hdr->seq) <= conn->last_recv_byte) {
		/* this is a DUP, send an ACK and avoid further processing */
		send_tcp_ack(conn);
		return;
	}

	if (len) {
		payload = ((char *) p->tcp_hdr) + (p->tcp_hdr->data_offset * 4);

		if (conn->data_len + len > TCP_WINDOW_SIZE) {
			send_tcp_rst(p, conn);
			remove_tcb(conn);

			return;
		}

		//TODO: check we do not go beyond the TCP receive window size
		memcpy(conn->data_buffer + conn->data_len, payload, len);
		conn->data_len += len;

		conn->last_recv_byte += len;
		send_tcp_ack(conn);

		if (p->tcp_hdr->flags & TCP_FLAG_PSH) {
			handle_http_request(conn);
		}

	}

	if (p->tcp_hdr->flags & TCP_FLAG_ACK) {

		 //TODO: check if something got missed and ask for retransmission
		conn->last_ackd_byte   = ntohl(p->tcp_hdr->ack);
		conn->effective_window = (ntohs(p->tcp_hdr->window) << conn->win_scale) -
			(conn->last_sent_byte - conn->last_ackd_byte);
	}
}

void
remove_tcb(tcp_conn_t *conn) {

	g_hash_table_remove(tcb_hash, conn->key);

	free(conn->key);
	free(conn);
}

void
process_tcp_fin(packet_t *p, tcp_conn_t *conn) {

	conn->last_recv_byte++;
	send_tcp_fin_ack(conn);

	conn->state = FIN_SENT;
}

void
process_closed_ack(packet_t *p, tcp_conn_t *conn) {

	/* TODO: check this is an ack to our FIN packet */
	log_debug1("connection closed");

	remove_tcb(conn);
}

void
process_tcp(packet_t *p) {

	p->tcp_hdr       = (tcp_hdr_t *) (p->buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));
	tcp_conn_t *conn = get_tcp_conn(p);

	if (conn) {
		/*
		 * this is a known connection
		 */
		switch (conn->state) {
			case ESTABLISHED:
				if (p->tcp_hdr->flags & TCP_FLAG_FIN) {
					log_debug1("recv tcp FIN packet");
					process_tcp_fin(p, conn);
				} else {
					log_debug1("recv tcp segment");
					process_tcp_segment(p, conn);
				}
				break;
			case SYN_RCVD:

				/*
				 * we would expect an ACK packet that concludes the 3WH
				 */
				process_3wh_ack(p, conn);
				break;

			case FIN_SENT:
				process_closed_ack(p, conn);
				break;
		}
	} else {
		if (likely(p->tcp_hdr->flags == TCP_FLAG_SYN)) {
			process_tcp_new_conn(p);
		} else {
			send_tcp_rst_without_conn(p);
		}
	}
}

static uint16_t
tcp_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, void *opts, uint32_t opts_len, void *data, uint32_t data_len) {

	uint32_t sum = 0;
	tcp_pseudo_header_t pseudo_hdr;

	pseudo_hdr.src_addr = ip_hdr->src_addr;
	pseudo_hdr.dst_addr = ip_hdr->dst_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.proto    = IP_PROTO_TCP;
	pseudo_hdr.length   = htons(sizeof(tcp_hdr_t) + opts_len + data_len);

	tcp_hdr->checksum   = 0;

	sum = partial_checksum(sum, (const uint8_t *) &pseudo_hdr, sizeof(tcp_pseudo_header_t));
	sum = partial_checksum(sum, (const uint8_t *) tcp_hdr, sizeof(tcp_hdr_t));
	sum = partial_checksum(sum, opts, opts_len);
	sum = finalize_checksum(sum, data, data_len);

	return sum;
}

int
tcp_conn_has_open_window(tcp_conn_t *conn) {

	return conn->effective_window > ETH_MTU;
}

int
tcp_conn_has_data_to_send(tcp_conn_t *conn) {

	return conn->http_response && conn->http_response->finished &&
		tcp_conn_has_open_window(conn);
}

void
tcp_conn_send_data_http_hdr(tcp_conn_t *conn, tcp_send_data_ctx_t *ctx) {
#define MAX_SLOT 100 /* XXX: find a good value for this */

	http_response_t *res;
	nm_tx_desc_t    tx_desc;

	char    *payload_buf;
	uint16_t payload_len = 0;

	res = conn->http_response;

	while (http_res_has_header_to_send(res) && tcp_conn_has_open_window(conn) && ctx->slot_count < MAX_SLOT) {
		if (unlikely(!nm_get_tx_buff_no_poll(&tx_desc))) {
			break;
		}

		payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc.buf);
		payload_len = MIN(ETH_MTU - sizeof(data_tcp_packet), res->header_len - res->header_pos);

		memcpy(payload_buf, res->header_buf + res->header_pos, payload_len);

		*tx_desc.len     = sizeof(data_tcp_packet) + payload_len;
		res->header_pos += payload_len;

		send_tcp_data(conn, tx_desc.buf, payload_buf, payload_len);

		conn->last_sent_byte   += payload_len;
		conn->effective_window -= payload_len;

		ctx->slot_count++;
	}

	ctx->http_hdr_last_tx_desc.buf = tx_desc.buf;
	ctx->http_hdr_last_tx_desc.len = tx_desc.len;

	ctx->last_http_hdr_pl_len      = payload_len;
}

void
tcp_conn_send_data_http_file(tcp_conn_t *conn, tcp_send_data_ctx_t *ctx) {

	http_response_t *res;
	nm_tx_desc_t    tx_desc[MAX_SLOT];
	struct iovec    iov[MAX_SLOT];
	int             iovcnt;

	size_t   start_pos;
	int      http_hdr_sent;

	char    *payload_buf;
	uint16_t payload_len;

	res                  = conn->http_response;
	iovcnt               = 0;
	start_pos            = res->file_pos;
	http_hdr_sent        = 0;

	/* if header fill up the packet, zero out last_http_hdr_pl_len */
	if (ctx->last_http_hdr_pl_len == ETH_MTU - sizeof(data_tcp_packet)) {
		ctx->last_http_hdr_pl_len = 0;
	}

	while (http_res_has_file_to_send(res) && tcp_conn_has_open_window(conn) && ctx->slot_count < MAX_SLOT) {
		if ((!http_hdr_sent) && ctx->last_http_hdr_pl_len) {
			/*
			 * here we are modifying the last packet, the one partially
			 * written with the last part of the HTTP header.
			 */
			tx_desc[0].buf = ctx->http_hdr_last_tx_desc.buf;
			tx_desc[0].len = ctx->http_hdr_last_tx_desc.len;

			conn->last_sent_byte   -= ctx->last_http_hdr_pl_len;
			conn->effective_window += ctx->last_http_hdr_pl_len;

			payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc->buf) + ctx->last_http_hdr_pl_len;
			payload_len = MIN(
				ETH_MTU - (sizeof(data_tcp_packet) + ctx->last_http_hdr_pl_len),
				res->file_len - res->file_pos
			);

			*tx_desc->len = sizeof(data_tcp_packet) + ctx->last_http_hdr_pl_len + payload_len;

			conn->effective_window -= ctx->last_http_hdr_pl_len + payload_len;
			http_hdr_sent = 1;

		} else {
			if (! nm_get_tx_buff_no_poll(&tx_desc[iovcnt])) {
				break;
			}

			payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc[iovcnt].buf);
			payload_len = MIN(
				ETH_MTU - sizeof(data_tcp_packet),
				res->file_len - res->file_pos
			);

			*tx_desc[iovcnt].len = sizeof(data_tcp_packet) + payload_len;
			conn->effective_window -= payload_len;
		}

		iov[iovcnt].iov_base = payload_buf;
		iov[iovcnt].iov_len  = payload_len;

		res->file_pos       += payload_len;

		ctx->slot_count++;
		iovcnt++;
	}

	if (likely(iovcnt > 0)) {
		preadv(res->file_fd, iov, iovcnt, start_pos);

		/*
		 * fix the first ring: we must consider the HTTP header
		 */
		iov[0].iov_base = (char *) iov[0].iov_base - ctx->last_http_hdr_pl_len;
		iov[0].iov_len  = iov[0].iov_len + ctx->last_http_hdr_pl_len;

		for (int i = 0; i < iovcnt; i++) {
			send_tcp_data(conn, tx_desc[i].buf, iov[i].iov_base, iov[i].iov_len);
			conn->last_sent_byte += iov[i].iov_len;
		}
	}
}

void
tcp_conn_send_data(tcp_conn_t *conn) {

	tcp_send_data_ctx_t ctx;
	http_response_t *res;

	ctx.slot_count           = 0;
	ctx.last_http_hdr_pl_len = 0;

	res = conn->http_response;

	tcp_conn_send_data_http_hdr(conn, &ctx);
	tcp_conn_send_data_http_file(conn, &ctx);

	if (! http_res_has_file_to_send(res)) {
		free(res->header_buf);
		free(res->parser);
		close(res->file_fd);
		free(res);

		conn->data_len      = 0;
		conn->http_response = NULL;
	}
}

static inline void
tcp_syn_ack_checksum() {

	syn_ack_tcp_packet.tcp.checksum =
		tcp_checksum(&syn_ack_tcp_packet.ip, &syn_ack_tcp_packet.tcp, &syn_ack_tcp_packet.opts, sizeof(tcp_syn_ack_opts_t), NULL, 0);
}

static inline void
tcp_ack_checksum() {

	ack_tcp_packet.tcp.checksum =
		tcp_checksum(&ack_tcp_packet.ip, &ack_tcp_packet.tcp, &ack_tcp_packet.opts, sizeof(tcp_ack_opts_t), NULL, 0);
}

static inline void
tcp_data_checksum(char *data, uint16_t data_len) {

	data_tcp_packet.tcp.checksum =
		tcp_checksum(&data_tcp_packet.ip, &data_tcp_packet.tcp, &data_tcp_packet.opts, sizeof(tcp_data_opts_t), data, data_len);
}

static inline void
tcp_fin_ack_checksum() {

	fin_ack_tcp_packet.tcp.checksum =
		tcp_checksum(&fin_ack_tcp_packet.ip, &fin_ack_tcp_packet.tcp, &fin_ack_tcp_packet.opts, sizeof(tcp_fin_ack_opts_t), NULL, 0);
}

static inline void
tcp_rst_checksum() {

	rst_tcp_packet.tcp.checksum =
		tcp_checksum(&rst_tcp_packet.ip, &rst_tcp_packet.tcp, NULL, 0, NULL, 0);
}

