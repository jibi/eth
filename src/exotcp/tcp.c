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

#include <eth/datastruct/list.h>
#include <eth/datastruct/hash.h>

#include <eth/mem_pool.h>

#include <eth/http11.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

/*
 * TCP control block hash table:
 * this table is used to keep track of all TCP connections.
 */
hash_table_t *tcb_hash;

/*
 * pointer to current connection
 */
tcp_conn_t   *cur_conn;

/*
 * list of tcp_per_conn_min_retx_ts_t:
 * each entry contains a tcp connection minimum retx timestamp
 */
list_head_t  per_conn_min_retx_ts;

mem_pool_t *unacked_segments_pool;

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
 * preinit packet: used to send data
 */
struct {
	eth_hdr_t       eth;
	ip_hdr_t        ip;
	tcp_hdr_t       tcp;
	tcp_data_opts_t opts;
} __attribute__ ((packed)) data_tcp_packet;

/*
 * preinit packet: sent to ack a fin packet
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
	uint16_t     last_http_hdr_pl_len;

} tcp_send_data_ctx_t;

static inline void tcp_syn_ack_checksum(void);
static inline void tcp_ack_checksum(void);
static inline void tcp_data_checksum(char *data, uint16_t data_len);
static inline void tcp_fin_ack_checksum(void);
static inline void tcp_rst_checksum(void);

static void track_unackd_segment(void);
static void ack_segment(void);

static inline
void
init_rtt(uint32_t echo_ts)
{
	cur_conn->rtt = cur_ms_ts() - echo_ts;
}

static inline
void
update_rtt(uint32_t echo_ts)
{
	uint32_t packet_rtt = cur_ms_ts() - echo_ts;

	/* FIXME: use Jacobson/Karels algorithm to calc RTT */
	cur_conn->rtt = (cur_conn->rtt * 0.8) + (packet_rtt * 0.2);
}

static inline
uint32_t
retx_ts(void)
{
	return cur_ms_ts() + MAX(cur_conn->rtt * 4, 10);
}

//returns x - y taking account of the wraparound
static inline
int
cmp_seq(uint32_t x, uint32_t y)
{
	uint32_t t = (0x80000000 - 1);

	return (x > y) ?
		(((x - y) > t) ? -(int32_t)(y - x) :  (int32_t)(x - y)) :
		(((y - x) > t) ?  (int32_t)(x - y) : -(int32_t)(y - x));
}

static inline
void
init_tcp_packet_header(tcp_hdr_t *hdr, uint8_t opts_len, uint8_t flags)
{
	hdr->src_port    = HTONS(listening_port);
	hdr->res         = 0;
	hdr->window      = HTONS(TCP_WINDOW_SIZE);
	hdr->data_offset = (sizeof(tcp_hdr_t) + opts_len) / 4;
	hdr->flags       = flags;
}

void
setup_tcp_hdr(tcp_hdr_t *hdr)
{
	hdr->dst_port = cur_sock->src_port;
	hdr->ack      = htonl(cur_conn->last_recv_byte + 1);
	hdr->seq      = htonl(cur_conn->last_sent_byte + 1);
	hdr->window   = HTONS(TCP_WINDOW_SIZE - cur_conn->data_len);
}

void
init_syn_ack_tcp_packet(void)
{
	init_eth_packet(&syn_ack_tcp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&syn_ack_tcp_packet.ip, sizeof(tcp_hdr_t) + sizeof(tcp_syn_ack_opts_t), IP_PROTO_TCP);
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
init_ack_tcp_packet(void)
{
	init_eth_packet(&ack_tcp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&ack_tcp_packet.ip, sizeof(tcp_hdr_t) + sizeof(tcp_ack_opts_t), IP_PROTO_TCP);
	init_tcp_packet_header(&ack_tcp_packet.tcp, sizeof(tcp_ack_opts_t), TCP_FLAG_ACK);

	ack_tcp_packet.opts = (tcp_ack_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_data_tcp_packet(void)
{
	init_eth_packet(&data_tcp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&data_tcp_packet.ip, 0, IP_PROTO_TCP);
	init_tcp_packet_header(&data_tcp_packet.tcp, sizeof(tcp_ack_opts_t), TCP_FLAG_ACK | TCP_FLAG_PSH);

	data_tcp_packet.opts = (tcp_data_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_fin_ack_tcp_packet(void)
{
	init_eth_packet(&fin_ack_tcp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&fin_ack_tcp_packet.ip, sizeof(tcp_hdr_t) + sizeof(tcp_fin_ack_opts_t), IP_PROTO_TCP);
	init_tcp_packet_header(&fin_ack_tcp_packet.tcp, sizeof(tcp_fin_ack_opts_t), TCP_FLAG_ACK | TCP_FLAG_FIN);

	fin_ack_tcp_packet.opts = (tcp_fin_ack_opts_t) {
		.ts  = { .code = TCP_OPT_TS_CODE, .len = TCP_OPT_TS_LEN},
		.nop = TCP_OPT_NOP_CODE,
		.eol = TCP_OPT_EOL_CODE
	};
}

void
init_rst_tcp_packet(void)
{
	init_eth_packet(&rst_tcp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&rst_tcp_packet.ip, sizeof(tcp_hdr_t), IP_PROTO_TCP);
	init_tcp_packet_header(&rst_tcp_packet.tcp, 0, TCP_FLAG_ACK | TCP_FLAG_RST);
}

bool
cmp_tcp_conn(void *t1, void *t2)
{
	return !memcmp(t1, t2, sizeof(tcp_conn_key_t));
}

uint32_t
tcp_key_hash_func(void *key)
{
	return murmur_hash(key, sizeof(tcp_conn_key_t), 0);
}

void
init_tcp(void)
{
	log_debug1("init_tcp");

	init_syn_ack_tcp_packet();
	init_ack_tcp_packet();
	init_data_tcp_packet();
	init_fin_ack_tcp_packet();
	init_rst_tcp_packet();

	tcb_hash = hash_table_init(tcp_key_hash_func, cmp_tcp_conn);

	list_init(&per_conn_min_retx_ts);

	unacked_segments_pool = mem_pool_new(sizeof(tcp_unackd_segment_t), 4096);
}

static inline
void
parse_tcp_options(tcp_hdr_t *tcp_hdr)
{
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
				cur_conn->client_opts.mss = ntohs((short) *(cur_opt + 2));
				log_debug2("\tmss: %d", cur_conn->client_opts.mss);

				cur_opt += 4;
				break;
			case 3:
				log_debug2("\twindow scaling");

				if (cur_conn->state == SYN_RCVD) {
					/* win scaling is only valid during the 3wh */
					cur_conn->client_opts.win_scale = *(cur_opt + 2);
				}

				cur_opt += 3;
				break;
			case 4:
				log_debug2("\tSACK permitted");

				if (cur_conn->state == SYN_RCVD) {
					/* SACK permitted is only valid during the 3wh */
					cur_conn->client_opts.sack_perm = 1;
				}

				cur_opt += 2;
				break;
			case 5:
				log_debug2("\tSACK");

				/* TODO: actually implement SACK */

				cur_opt += *(cur_opt + 1);
				break;
			case 8:
				cur_conn->client_opts.ts      = *((int *) (cur_opt + 2));
				cur_conn->client_opts.echo_ts = *((int *) (cur_opt + 6));

				log_debug2("\ts: %d; echo ts: %d", ntohl(cur_conn->client_opts.ts), ntohl(cur_conn->client_opts.echo_ts));

				if (cur_conn->client_opts.echo_ts) {
					switch (cur_conn->state) {
						case ESTABLISHED: update_rtt(ntohl(cur_conn->client_opts.echo_ts)); break;
						case SYN_SENT:    init_rtt(ntohl(cur_conn->client_opts.echo_ts));   break;
						default: ;
					}
				}

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

static inline
void
send_tcp_syn_ack(void)
{
	log_debug1("send tcp SYN+ACK packet");

	setup_eth_hdr(&syn_ack_tcp_packet.eth);
	setup_ip_hdr(&syn_ack_tcp_packet.ip, 0);
	setup_tcp_hdr(&syn_ack_tcp_packet.tcp);

	/* XXX */
	syn_ack_tcp_packet.opts.mss.size        = HTONS(TCP_MSS);
	syn_ack_tcp_packet.opts.ts.ts           = htonl(cur_ms_ts());
	syn_ack_tcp_packet.opts.ts.echo         = cur_conn->client_opts.ts;
	syn_ack_tcp_packet.opts.win_scale.shift = TCP_WIN_SCALE;

	tcp_syn_ack_checksum();

	nm_send_packet(&syn_ack_tcp_packet, sizeof(syn_ack_tcp_packet));
}

static inline
void
send_tcp_ack(void)
{
	log_debug1("send tcp ACK packet");

	setup_eth_hdr(&ack_tcp_packet.eth);
	setup_ip_hdr(&ack_tcp_packet.ip, 0);
	setup_tcp_hdr(&ack_tcp_packet.tcp);

	ack_tcp_packet.opts.ts.ts   = htonl(cur_ms_ts());
	ack_tcp_packet.opts.ts.echo = cur_conn->client_opts.ts;

	tcp_ack_checksum();

	nm_send_packet(&ack_tcp_packet, sizeof(ack_tcp_packet));
}

static inline
void
send_tcp_data(char *packet_buf, char *data, uint16_t len)
{
	log_debug1("send tcp data packet");

	setup_eth_hdr(&data_tcp_packet.eth);
	setup_ip_hdr(&data_tcp_packet.ip, sizeof(tcp_hdr_t) + sizeof(tcp_data_opts_t) + len);
	setup_tcp_hdr(&data_tcp_packet.tcp);

	data_tcp_packet.opts.ts.ts   = htonl(cur_ms_ts());
	data_tcp_packet.opts.ts.echo = cur_conn->client_opts.ts;

#ifdef DEBUG_TCP_RETX
	static int i = 1;
	if (i++ % 100000)
#endif
	tcp_data_checksum(data, len);

	track_unackd_segment();

	memcpy(packet_buf, &data_tcp_packet, sizeof(data_tcp_packet));
}

static inline
void
send_tcp_data_retx(char *packet_buf, char *data, uint16_t len, uint32_t seq)
{
	log_debug1("send (retx) tcp data packet");

	setup_eth_hdr(&data_tcp_packet.eth);
	setup_ip_hdr(&data_tcp_packet.ip, sizeof(tcp_hdr_t) + sizeof(tcp_data_opts_t) + len);
	setup_tcp_hdr(&data_tcp_packet.tcp);

	data_tcp_packet.tcp.seq      = htonl(seq);
	data_tcp_packet.opts.ts.ts   = htonl(cur_ms_ts());
	data_tcp_packet.opts.ts.echo = cur_conn->client_opts.ts;

	tcp_data_checksum(data, len);

	memcpy(packet_buf, &data_tcp_packet, sizeof(data_tcp_packet));
}

static inline
void
send_tcp_fin_ack(void)
{
	log_debug1("send tcp FIN+ACK packet");

	setup_eth_hdr(&fin_ack_tcp_packet.eth);
	setup_ip_hdr(&fin_ack_tcp_packet.ip, 0);
	setup_tcp_hdr(&fin_ack_tcp_packet.tcp);

	fin_ack_tcp_packet.opts.ts.ts   = htonl(cur_ms_ts());
	fin_ack_tcp_packet.opts.ts.echo = cur_conn->client_opts.ts;

	tcp_fin_ack_checksum();

	nm_send_packet(&fin_ack_tcp_packet, sizeof(fin_ack_tcp_packet));
}

static inline
void
send_tcp_rst(void)
{
	log_debug1("send tcp RST packet");

	setup_eth_hdr(&rst_tcp_packet.eth);
	setup_ip_hdr(&rst_tcp_packet.ip, 0);
	setup_tcp_hdr(&rst_tcp_packet.tcp);

	rst_tcp_packet.tcp.src_port = cur_pkt->tcp_hdr->dst_port;

	tcp_rst_checksum();

	nm_send_packet(&rst_tcp_packet, sizeof(rst_tcp_packet));
}

static inline
void
send_tcp_rst_without_conn(void)
{
	/*
	 * build a fake conn to make send_tcp_rst happy
	 */
	tcp_conn_t conn;

	conn.last_recv_byte = ntohl(cur_pkt->tcp_hdr->seq);
	conn.last_sent_byte = 1;
	conn.data_len       = 0;

	set_cur_conn(&conn);

	send_tcp_rst();
}

static inline
tcp_conn_t *
new_tcp_conn()
{
	struct timeval tv;
	int rand_seq;

	tcp_conn_key_t *conn_key = malloc(sizeof(tcp_conn_key_t));
	tcp_conn_t     *conn     = malloc(sizeof(tcp_conn_t));

	gettimeofday(&tv, 0);

	/*
	 * we do not want to start with a sequence number equal to zero.
	 * Since we send everytime (last_sent_byte + 1), we have to make sure that
	 * (rand_seq + 1) != 0
	 * */
	do {
		rand_seq = rand();
	} while (!(rand_seq + 1));

	conn->key             = conn_key;
	conn->key->src_port   = cur_pkt->tcp_hdr->src_port;
	conn->key->src_addr   = cur_pkt->ip_hdr->src_addr;

	conn->sock            = malloc(sizeof(socket_t));
	memcpy(conn->sock, cur_sock, sizeof(socket_t));

	conn->last_recv_byte  = ntohl(cur_pkt->tcp_hdr->seq);
	conn->last_sent_byte  = rand_seq;
	conn->state           = SYN_RCVD;
	conn->recv_eff_window = 0;
	conn->data_len        = 0;
	conn->http_response   = NULL;

	conn->rtt             = 1000;

	conn->client_opts.win_scale = 0;
	conn->client_opts.sack_perm = 0;

	conn->last_retx_seg_seq = 0;
	conn->last_retx_seg_ts  = 0;

	hash_table_insert(tcb_hash, conn->key, conn);
	list_add(&conn->nm_tcp_conn_list_head, nm_tcp_conn_list);

	list_init(&conn->unackd_segs);
	conn->min_retx_ts.conn = conn;

	conn->min_retx_ts.head.next = NULL;
	conn->min_retx_ts.head.prev = NULL;

	return conn;
}

static inline
void
delete_tcp_conn(void)
{
	hash_table_remove(tcb_hash, cur_conn->key);
	/*
	 * if this is the current connection on which nm send loop is
	 * iterating, update it to point to the next entry
	 */
	if (nm_send_loop_cur_conn == cur_conn) {
		nm_send_loop_cur_conn = list_next_entry(nm_send_loop_cur_conn, nm_tcp_conn_list_head);
	}

	/* delete conn from nm global conn list */
	list_del(&cur_conn->nm_tcp_conn_list_head);

	/* delete conn min retx entry from global retx list */
	if (list_head_attached(&cur_conn->min_retx_ts.head)) {
		list_del(&cur_conn->min_retx_ts.head);
	}

	free(cur_conn->key);
	free(cur_conn);
}

static inline
void
process_tcp_new_conn(void)
{
	tcp_conn_t *conn;

	if (unlikely(ntohs(cur_pkt->tcp_hdr->dst_port) != listening_port)) {
		send_tcp_rst_without_conn();

		return;
	}

	log_debug1("recv tcp SYN packet");

	conn = new_tcp_conn();
	set_cur_conn(conn);

	if (tcp_has_options(cur_pkt->tcp_hdr)) {
		parse_tcp_options(cur_pkt->tcp_hdr);
	}

	send_tcp_syn_ack();

	/*
	 * a packet with the SYN flag require us to increment the sequence
	 * number by 1
	 */
	conn->last_ackd_byte = ntohl(cur_pkt->tcp_hdr->ack);
	conn->last_sent_byte++;
	conn->state = SYN_SENT;
}

static inline
tcp_conn_t *
get_tcp_conn(void)
{
	uint8_t *a = (uint8_t *) &cur_pkt->ip_hdr->src_addr;
	log_debug2("get_tcp_conn: address %d.%d.%d.%d, port %d", a[0], a[1], a[2], a[3], cur_pkt->tcp_hdr->src_port);

	tcp_conn_key_t key = {
		.src_port = cur_pkt->tcp_hdr->src_port,
		.src_addr = cur_pkt->ip_hdr->src_addr
	};

	return hash_table_lookup(tcb_hash, &key);
}

static inline
void
process_3wh_ack(void)
{
	if (cur_pkt->tcp_hdr->data_offset > 5) {
		parse_tcp_options(cur_pkt->tcp_hdr);
	}

	/* TODO: check ack number */

	log_debug1("new connection established");
	cur_conn->state = ESTABLISHED;
}

static inline
void
process_tcp_segment_data(void)
{
	char     *payload = ((char *) cur_pkt->tcp_hdr) + (cur_pkt->tcp_hdr->data_offset * 4);
	uint16_t len      = tcp_payload_len(cur_pkt);

	if (cur_conn->data_len + len > TCP_WINDOW_SIZE) {
		send_tcp_rst();
		delete_tcp_conn();

		return;
	}

	//TODO: check we do not go beyond the TCP receive window size
	memcpy(cur_conn->data_buffer + cur_conn->data_len, payload, len);
	cur_conn->data_len += len;

	cur_conn->last_recv_byte += len;

	if (flag_psh(cur_pkt->tcp_hdr)) {
		handle_http_request();

		if (cur_conn->http_response->parser->parsed) {
			cur_conn->http_response_start_seq = cur_conn->last_sent_byte + 1;
		}
	}
}

static inline
void
update_tcp_eff_window() {
	uint16_t adv_win   = ntohs(cur_pkt->tcp_hdr->window);
	uint8_t  win_scale = cur_conn->client_opts.win_scale;

	cur_conn->recv_eff_window = (adv_win << win_scale) - (cur_conn->last_sent_byte - cur_conn->last_ackd_byte);
}

static inline
bool
tcp_seq_is_dup() {
	return cmp_seq(ntohl(cur_pkt->tcp_hdr->seq), cur_conn->last_recv_byte) <= 0;
}

static inline
void
process_tcp_segment_ack(void)
{
	uint32_t new_ack;
	tcp_unackd_segment_t *seg;

	new_ack = ntohl(cur_pkt->tcp_hdr->ack);

	if (cur_conn->last_ackd_byte == new_ack) {
		if (cur_conn->last_retx_seg_seq == new_ack && cur_ms_ts() <= cur_conn->last_retx_seg_ts) {
			/*
			 * if this is an ack to the segment just before the last one we had
			 * retransmitted, and the 4 * rtt timeout has not elapsed, do not
			 * retransmit. Since we send x packets in a row, chances are we receive
			 * x ACK packets all equals.
			 */

			return;
		}

		list_for_each_entry(seg, &cur_conn->unackd_segs, head) {
			if (seg->seq == new_ack) {
				tcp_retransm_segment(seg);
				break;
			}
		}
	} else {
		cur_conn->last_ackd_byte = new_ack;
		update_tcp_eff_window();

		ack_segment();
	}
}

static inline
void
process_tcp_segment_no_dup() {
	parse_tcp_options(cur_pkt->tcp_hdr);

	if (tcp_payload_len(cur_pkt)) {
		process_tcp_segment_data();
		send_tcp_ack();
	}

	if (flag_ack(cur_pkt->tcp_hdr)) {
		process_tcp_segment_ack();
	}
}

static inline
void
process_tcp_segment_dup() {
	send_tcp_ack();
}

static inline
void
process_tcp_segment(void)
{
	log_debug1("recv tcp segment");

	/*
	 * normally last_recv_byte should be equal to cur_pkt' seq - 1
	 * (so the cmp function must return something greater than 0)
	 */
	if (likely(! tcp_seq_is_dup())) {
		process_tcp_segment_no_dup();
	} else {
		process_tcp_segment_dup();
	}

	 //TODO: check if something got missed and ask for retransmission
}

static inline
void
process_tcp_fin(void)
{
	log_debug1("recv tcp FIN packet");

	cur_conn->last_recv_byte++;
	send_tcp_fin_ack();

	cur_conn->state = FIN_SENT;
}

static inline
void
process_closed_ack(void)
{
	/* TODO: check this is an ack to our FIN packet */
	log_debug1("connection closed");

	delete_tcp_conn();
}

static inline
void
process_tcp_with_conn() {
	switch (cur_conn->state) {
		case ESTABLISHED:
			if (flag_fin(cur_pkt->tcp_hdr)) {
				process_tcp_fin();
			} else {
				process_tcp_segment();
			}
			break;

		case SYN_SENT:
			process_3wh_ack();
			break;

		case FIN_SENT:
			process_closed_ack();
			break;

		default: ;
	}
}

static inline
void
process_tcp_without_conn(void) {
	if (flag_syn(cur_pkt->tcp_hdr)) {
		process_tcp_new_conn();
	} else {
		send_tcp_rst_without_conn();
	}
}

void
process_tcp(void)
{
	tcp_conn_t *conn;

	cur_pkt->tcp_hdr   = (tcp_hdr_t *) (cur_pkt->buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));
	cur_sock->src_port = cur_pkt->tcp_hdr->src_port;
	conn               = get_tcp_conn();

	if (conn) {
		set_cur_conn(conn);
		process_tcp_with_conn();
	} else {
		process_tcp_without_conn();
	}
}

static
uint16_t
tcp_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, void *opts, uint32_t opts_len, void *data, uint32_t data_len)
{
	uint64_t sum = 0;
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

#define MAX_SLOT 256 /* TODO: use NIC ring size */

void
tcp_conn_send_data_http_hdr(tcp_send_data_ctx_t *ctx)
{

	http_response_t *res;
	nm_tx_desc_t    tx_desc;

	char    *payload_buf;
	uint16_t payload_len = 0;

	res = cur_conn->http_response;

	while (http_res_has_header_to_send(res) && tcp_conn_has_open_window()) {
		if (unlikely(nm_send_ring_empty())) {
			break;
		}

		nm_get_tx_buff(&tx_desc);

		payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc.buf);
		payload_len = MIN(ETH_MTU - sizeof(data_tcp_packet), res->header_len - res->header_pos);

		memcpy(payload_buf, res->header_buf + res->header_pos, payload_len);

		*tx_desc.len     = sizeof(data_tcp_packet) + payload_len;
		res->header_pos += payload_len;

		/*
		 * send this frame only if:
		 *
		 * * payload's length is equal to MSS or
		 * * payload's length is not equal to MSS but there's no more
		 * data to send (i.e. file_len is 0)
		 */
		if (payload_len == cur_conn->client_opts.mss - sizeof(tcp_data_opts_t) || res->file_len == 0) {
			send_tcp_data(tx_desc.buf, payload_buf, payload_len);

			cur_conn->last_sent_byte  += payload_len;
			cur_conn->recv_eff_window -= payload_len;

		} else {
			ctx->http_hdr_last_tx_desc.buf = tx_desc.buf;
			ctx->http_hdr_last_tx_desc.len = tx_desc.len;

			ctx->last_http_hdr_pl_len      = payload_len;

			break;
		}
	}
}

void
tcp_conn_send_data_http_file(tcp_send_data_ctx_t *ctx)
{
	http_response_t *res;
	nm_tx_desc_t    tx_desc[MAX_SLOT];
	struct iovec    iov[MAX_SLOT];
	int             iovcnt;

	size_t   start_pos;

	char    *payload_buf;
	uint16_t payload_len;
	uint16_t payload_offset;

	res            = cur_conn->http_response;
	iovcnt         = 0;
	start_pos      = res->file_pos;
	payload_offset = ctx->last_http_hdr_pl_len;

	while (http_res_has_file_to_send(res) && tcp_conn_has_open_window()) {
		if (unlikely(nm_send_ring_empty())) {
			break;
		}

		/*
		 * payload_offset specifies the offset which we need to use to
		 * start write the file into the first packet (because we are
		 * writing a packet that was partially written by the
		 * tcp_cond_send_data_http_header function).
		 */

		/* TODO: maybe factorize this */
		if (unlikely(payload_offset)) {
			/*
			 * here we are modifying the last packet, the one partially
			 * written with the last part of the HTTP header.
			 */
			tx_desc[iovcnt].buf = ctx->http_hdr_last_tx_desc.buf;
			tx_desc[iovcnt].len = ctx->http_hdr_last_tx_desc.len;

			payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc[iovcnt].buf) + payload_offset;
			payload_len = MIN(ETH_MTU - (sizeof(data_tcp_packet) + payload_offset), res->file_len - res->file_pos);

			*tx_desc[iovcnt].len = sizeof(data_tcp_packet) + payload_offset + payload_len;
			cur_conn->recv_eff_window -= payload_offset + payload_len;

			payload_offset = 0;
		} else {
			nm_get_tx_buff(&tx_desc[iovcnt]);

			payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc[iovcnt].buf);
			payload_len = MIN(ETH_MTU - sizeof(data_tcp_packet), res->file_len - res->file_pos);

			*tx_desc[iovcnt].len       = sizeof(data_tcp_packet) + payload_len;
			cur_conn->recv_eff_window -= payload_len;
		}

		iov[iovcnt].iov_base = payload_buf;
		iov[iovcnt].iov_len  = payload_len;
		res->file_pos       += payload_len;

		iovcnt++;
	}

	if (likely(iovcnt > 0)) {
		preadv(res->file_fd, iov, iovcnt, start_pos);

		/*
		 * fix the first ring: we must consider the possible HTTP header
		 */
		if (ctx->last_http_hdr_pl_len) {
			iov[0].iov_base = (char *) iov[0].iov_base - ctx->last_http_hdr_pl_len;
			iov[0].iov_len  = iov[0].iov_len + ctx->last_http_hdr_pl_len;
		}

		for (int i = 0; i < iovcnt; i++) {
			send_tcp_data(tx_desc[i].buf, iov[i].iov_base, iov[i].iov_len);
			cur_conn->last_sent_byte += iov[i].iov_len;
		}
	}
}

void
tcp_conn_send_data(void)
{
	tcp_send_data_ctx_t ctx;
	http_response_t *res;

	ctx.last_http_hdr_pl_len = 0;

	res = cur_conn->http_response;

	tcp_conn_send_data_http_hdr(&ctx);
	tcp_conn_send_data_http_file(&ctx);

	if (! http_res_has_file_to_send(res)) {
		res->sent = true;

		/*
		 * since we just finished to send the HTTP response, we are for sure still
		 * waiting for the ACKs, so we can't just free here the http response (in
		 * case we need to retx).
		 */
	}
}

static inline
void
tcp_syn_ack_checksum(void)
{
	syn_ack_tcp_packet.tcp.checksum =
		tcp_checksum(&syn_ack_tcp_packet.ip, &syn_ack_tcp_packet.tcp, &syn_ack_tcp_packet.opts, sizeof(tcp_syn_ack_opts_t), NULL, 0);
}

static inline
void
tcp_ack_checksum(void)
{
	ack_tcp_packet.tcp.checksum =
		tcp_checksum(&ack_tcp_packet.ip, &ack_tcp_packet.tcp, &ack_tcp_packet.opts, sizeof(tcp_ack_opts_t), NULL, 0);
}

static inline
void
tcp_data_checksum(char *data, uint16_t data_len)
{
	data_tcp_packet.tcp.checksum =
		tcp_checksum(&data_tcp_packet.ip, &data_tcp_packet.tcp, &data_tcp_packet.opts, sizeof(tcp_data_opts_t), data, data_len);
}

static inline
void
tcp_fin_ack_checksum(void)
{
	fin_ack_tcp_packet.tcp.checksum =
		tcp_checksum(&fin_ack_tcp_packet.ip, &fin_ack_tcp_packet.tcp, &fin_ack_tcp_packet.opts, sizeof(tcp_fin_ack_opts_t), NULL, 0);
}

static inline
void
tcp_rst_checksum(void)
{
	rst_tcp_packet.tcp.checksum =
		tcp_checksum(&rst_tcp_packet.ip, &rst_tcp_packet.tcp, NULL, 0, NULL, 0);
}

static inline
void
track_unackd_segment(void)
{
	uint32_t seq              = cur_conn->last_sent_byte + 1;
	tcp_unackd_segment_t *seg = mem_pool_malloc(unacked_segments_pool);

	seg->seq     = seq;
	seg->retx_ts = retx_ts();

	list_add_tail(&seg->head, &cur_conn->unackd_segs);

	/*
	 * if there were no unackd segments for this connection before, we need to add
	 * the entry to the global min_rets_ts list
	 */
	if (!list_head_attached(&cur_conn->min_retx_ts.head)) {
		list_add(&cur_conn->min_retx_ts.head, &per_conn_min_retx_ts);
	}

	log_debug2("tracking unackd segment %d (conn %p)", seq, cur_conn);
}

static
int
cmp_unackd_seg(void *data, list_head_t *a, list_head_t *b)
{
	tcp_unackd_segment_t *_a = list_entry(a, tcp_unackd_segment_t, head);
	tcp_unackd_segment_t *_b = list_entry(b, tcp_unackd_segment_t, head);

	return _a->retx_ts - _b->retx_ts;
}

static
int
cmp_min_retx_ts(void *data, list_head_t *a, list_head_t *b)
{
	tcp_per_conn_min_retx_ts_t *_a = list_entry(a, tcp_per_conn_min_retx_ts_t, head);
	tcp_per_conn_min_retx_ts_t *_b = list_entry(b, tcp_per_conn_min_retx_ts_t, head);

	return _a->retx_ts - _b->retx_ts;
}

void
sort_unackd_segments(void)
{
	list_sort(NULL, &cur_conn->unackd_segs, cmp_unackd_seg);
}

void
sort_min_retx_ts(void)
{
	list_sort(NULL, &per_conn_min_retx_ts, cmp_min_retx_ts);
}

static inline
void
ack_segment(void)
{
	uint32_t seq;

	tcp_unackd_segment_t *seg;
	tcp_unackd_segment_t *tmp;

	seq = cur_conn->last_ackd_byte;

	list_for_each_entry_safe(seg, tmp, &cur_conn->unackd_segs, head) {
		if (cmp_seq(seg->seq, seq) < 0) {
			log_debug2("removing segment %d (conn %p) from unacked segments array", seg->seq, cur_conn);

			list_del(&seg->head);
			mem_pool_free(unacked_segments_pool, seg);
		}
	}

	if (list_empty(&cur_conn->unackd_segs) && list_head_attached(&cur_conn->min_retx_ts.head)) {
		list_del(&cur_conn->min_retx_ts.head);

		if (cur_conn->http_response->sent) {
			free_http_response();
		}
	}
}

void
tcp_retransm_segment(tcp_unackd_segment_t *seg)
{
	http_response_t *res;

	uint32_t start_byte;
	uint32_t header_start;
	uint32_t header_len;
	uint32_t file_start;
	uint32_t file_len;

	nm_tx_desc_t tx_desc;

	char    *payload_buf;
	uint16_t payload_len;
	uint32_t seq;

	header_start = 0;
	file_start   = 0;
	seq          = seg->seq;
	start_byte   = cmp_seq(seq, cur_conn->http_response_start_seq);

	res = cur_conn->http_response;

	if (start_byte < res->header_len) {
		header_start = start_byte;
		header_len   = MIN(cur_conn->client_opts.mss - sizeof(tcp_data_opts_t), res->header_len - header_start);
	} else {
		header_len = 0;
	}

	if (ETH_MTU - sizeof(data_tcp_packet) - header_len > 0) {
		file_start = start_byte - res->header_len;
		file_len   = MIN(cur_conn->client_opts.mss - sizeof(tcp_data_opts_t) - header_len, res->file_len - file_start);
	} else {
		file_len   = 0;
	}

	nm_get_tx_buff(&tx_desc);

	payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_desc.buf);
	payload_len = header_len + file_len;

	*tx_desc.len               = sizeof(data_tcp_packet) + payload_len;
	cur_conn->recv_eff_window -= payload_len;

	memcpy(payload_buf, res->header_buf + header_start, header_len);
	pread(res->file_fd, payload_buf + header_len, file_len, file_start);

	send_tcp_data_retx(tx_desc.buf, payload_buf, payload_len, seq);

	seg->retx_ts = retx_ts();

	cur_conn->last_retx_seg_seq = seg->seq;
	cur_conn->last_retx_seg_ts  = seg->retx_ts;
}

