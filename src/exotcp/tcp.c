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

static uint16_t tcp_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, void *opts, uint32_t opts_len, void *data, uint32_t data_len);
#define tcp_syn_ack_checksum(ip_hdr, tcp_hdr, opts) \
	tcp_checksum(ip_hdr, tcp_hdr, opts, sizeof(tcp_syn_ack_opts_t), NULL, 0)
#define tcp_ack_checksum(ip_hdr, tcp_hdr, opts) \
	tcp_checksum(ip_hdr, tcp_hdr, opts, sizeof(tcp_ack_opts_t), NULL, 0)
#define tcp_data_checksum(ip_hdr, tcp_hdr, opts, data, data_len) \
	tcp_checksum(ip_hdr, tcp_hdr, opts, sizeof(tcp_data_opts_t), data, data_len)
#define tcp_fin_ack_checksum(ip_hdr, tcp_hdr, opts) \
	tcp_checksum(ip_hdr, tcp_hdr, opts, sizeof(tcp_fin_ack_opts_t), NULL, 0)
#define tcp_rst_checksum(ip_hdr, tcp_hdr) \
	tcp_checksum(ip_hdr, tcp_hdr, NULL, 0, NULL, 0)
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
init_syn_ack_tcp_packet() {
	/*
	 * tcp header
	 */

	syn_ack_tcp_packet.tcp.src_port    = HTONS(listening_port);
	syn_ack_tcp_packet.tcp.res         = 0;

	/* TODO: comply to TCP window size */
	syn_ack_tcp_packet.tcp.window      = HTONS(TCP_WINDOW_SIZE);
	syn_ack_tcp_packet.tcp.data_offset = (sizeof(tcp_hdr_t) + sizeof(tcp_syn_ack_opts_t)) / 4;
	syn_ack_tcp_packet.tcp.flags       = (TCP_FLAG_SYN | TCP_FLAG_ACK);

	/*
	 * tcp opts
	 */

	/* TODO: negotiate MSS */
	syn_ack_tcp_packet.opts.mss.code       = TCP_OPT_MSS_CODE;
	syn_ack_tcp_packet.opts.mss.len        = TCP_OPT_MSS_LEN;

	syn_ack_tcp_packet.opts.sack_perm.code = TCP_OPT_SACK_PERM_CODE;
	syn_ack_tcp_packet.opts.sack_perm.len  = TCP_OPT_SACK_PERM_LEN;

	syn_ack_tcp_packet.opts.win_scale.code = TCP_OPT_WIN_SCALE_CODE;
	syn_ack_tcp_packet.opts.win_scale.len  = TCP_OPT_WIN_SCALE_LEN;

	syn_ack_tcp_packet.opts.ts.code        = TCP_OPT_TS_CODE;
	syn_ack_tcp_packet.opts.ts.len         = TCP_OPT_TS_LEN;

	syn_ack_tcp_packet.opts.eol            = TCP_OPT_EOL_CODE;

	/*
	 * ip header
	 */

	init_ip_packet(&syn_ack_tcp_packet.ip, sizeof(tcp_syn_ack_opts_t), 0);

	/*
	 * eth header
	 */
	memcpy(syn_ack_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	syn_ack_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
}

void
init_ack_tcp_packet() {
	/*
	 * tcp header
	 */
	ack_tcp_packet.tcp.src_port    = HTONS(listening_port);
	ack_tcp_packet.tcp.res         = 0;
	ack_tcp_packet.tcp.window      = HTONS(TCP_WINDOW_SIZE); /* XXX: subtract buffer len */
	ack_tcp_packet.tcp.data_offset = (sizeof(tcp_hdr_t) + sizeof(tcp_ack_opts_t)) / 4;
	ack_tcp_packet.tcp.flags       = TCP_FLAG_ACK;

	/*
	 * tcp opts
	 */
	ack_tcp_packet.opts.ts.code = TCP_OPT_TS_CODE;
	ack_tcp_packet.opts.ts.len  = TCP_OPT_TS_LEN;

	ack_tcp_packet.opts.nop     = TCP_OPT_NOP_CODE;
	ack_tcp_packet.opts.eol     = TCP_OPT_EOL_CODE;

	/*
	 * ip header
	 */

	init_ip_packet(&ack_tcp_packet.ip, sizeof(tcp_ack_opts_t), 0);

	/*
	 * eth header
	 */
	memcpy(ack_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	ack_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
}

void
init_data_tcp_packet() {
	/*
	 * tcp header
	 */
	data_tcp_packet.tcp.src_port    = HTONS(listening_port);
	data_tcp_packet.tcp.res         = 0;
	data_tcp_packet.tcp.window      = HTONS(TCP_WINDOW_SIZE); /* XXX: subtract buffer len */
	data_tcp_packet.tcp.data_offset = (sizeof(tcp_hdr_t) + sizeof(tcp_ack_opts_t)) / 4;
	data_tcp_packet.tcp.flags       = TCP_FLAG_ACK | TCP_FLAG_PSH;

	/*
	 * tcp opts
	 */
	data_tcp_packet.opts.ts.code = TCP_OPT_TS_CODE;
	data_tcp_packet.opts.ts.len  = TCP_OPT_TS_LEN;

	data_tcp_packet.opts.nop     = TCP_OPT_NOP_CODE;
	data_tcp_packet.opts.eol     = TCP_OPT_EOL_CODE;

	/*
	 * ip header
	 */

	init_ip_packet(&data_tcp_packet.ip, sizeof(tcp_data_opts_t), 0);

	/*
	 * eth header
	 */
	memcpy(data_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	data_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
}

void
init_fin_ack_tcp_packet() {
	/*
	 * tcp header
	 */
	fin_ack_tcp_packet.tcp.src_port    = HTONS(listening_port);
	fin_ack_tcp_packet.tcp.res         = 0;
	fin_ack_tcp_packet.tcp.window      = HTONS(TCP_WINDOW_SIZE); /* XXX: subtract buffer len */
	fin_ack_tcp_packet.tcp.data_offset = (sizeof(tcp_hdr_t) + sizeof(tcp_fin_ack_opts_t)) / 4;
	fin_ack_tcp_packet.tcp.flags       = TCP_FLAG_FIN | TCP_FLAG_ACK;

	/*
	 * tcp opts
	 */
	fin_ack_tcp_packet.opts.ts.code = TCP_OPT_TS_CODE;
	fin_ack_tcp_packet.opts.ts.len  = TCP_OPT_TS_LEN;

	fin_ack_tcp_packet.opts.nop     = TCP_OPT_NOP_CODE;
	fin_ack_tcp_packet.opts.eol     = TCP_OPT_EOL_CODE;

	/*
	 * ip header
	 */

	init_ip_packet(&fin_ack_tcp_packet.ip, sizeof(tcp_fin_ack_opts_t), 0);

	/*
	 * eth header
	 */
	memcpy(fin_ack_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	fin_ack_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
}

void
init_rst_tcp_packet() {
	/*
	 * tcp header
	 */
	rst_tcp_packet.tcp.src_port    = HTONS(listening_port);
	rst_tcp_packet.tcp.res         = 0;
	rst_tcp_packet.tcp.window      = HTONS(TCP_WINDOW_SIZE); /* XXX: subtract buffer len */
	rst_tcp_packet.tcp.data_offset = sizeof(tcp_hdr_t) / 4;
	rst_tcp_packet.tcp.flags       = TCP_FLAG_RST | TCP_FLAG_ACK;

	/*
	 * ip header
	 */

	init_ip_packet(&rst_tcp_packet.ip, 0, 0);

	/*
	 * eth header
	 */
	memcpy(rst_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	rst_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
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
					conn->win_scale = (short) *(cur_opt + 2);
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
send_tcp_syn_ack(packet_t *p, tcp_conn_t *conn) {

	netmap_tx_ring_desc_t tx_desc;
	log_debug1("send tcp SYN+ACK packet");

	/* XXX */
	syn_ack_tcp_packet.opts.mss.size        = HTONS(TCP_MSS);
	syn_ack_tcp_packet.opts.ts.ts           = htonl(get_tcp_clock(conn));
	syn_ack_tcp_packet.opts.ts.echo         = conn->ts;
	syn_ack_tcp_packet.opts.win_scale.shift = TCP_WIN_SCALE;

	syn_ack_tcp_packet.tcp.dst_port         = p->tcp_hdr->src_port;

	/*
	 * with a SYN packet we need to ACK one byte.
	 */
	syn_ack_tcp_packet.tcp.ack              = htonl(conn->last_recv_byte + 1);
	syn_ack_tcp_packet.tcp.seq              = htonl(conn->last_sent_byte);
	syn_ack_tcp_packet.tcp.checksum         = 0;

	memcpy(&syn_ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	syn_ack_tcp_packet.ip.check = 0;
	syn_ack_tcp_packet.ip.check = checksum((uint8_t *) &syn_ack_tcp_packet.ip, sizeof(ip_hdr_t));

	syn_ack_tcp_packet.tcp.checksum = tcp_syn_ack_checksum(&syn_ack_tcp_packet.ip, &syn_ack_tcp_packet.tcp, &syn_ack_tcp_packet.opts);

	memcpy(syn_ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	netmap_get_tx_ring_buffer(&tx_desc);
	memcpy(tx_desc.buf, &syn_ack_tcp_packet, sizeof(syn_ack_tcp_packet));
	*tx_desc.len = sizeof(syn_ack_tcp_packet);

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
send_tcp_ack(packet_t *p, tcp_conn_t *conn) {

	netmap_tx_ring_desc_t tx_desc;
	log_debug1("send tcp ACK packet");

	ack_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	ack_tcp_packet.opts.ts.echo = conn->ts;

	ack_tcp_packet.tcp.dst_port = p->tcp_hdr->src_port;
	ack_tcp_packet.tcp.ack      = htonl(conn->last_recv_byte + 1);
	ack_tcp_packet.tcp.seq      = htonl(conn->last_sent_byte);
	ack_tcp_packet.tcp.checksum = 0;

	memcpy(&ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	ack_tcp_packet.ip.check = 0;
	ack_tcp_packet.ip.check = checksum((uint8_t *) &ack_tcp_packet.ip, sizeof(ip_hdr_t));

	ack_tcp_packet.tcp.checksum = tcp_ack_checksum(&ack_tcp_packet.ip, &ack_tcp_packet.tcp, &ack_tcp_packet.opts);

	memcpy(ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	netmap_get_tx_ring_buffer(&tx_desc);
	memcpy(tx_desc.buf, &ack_tcp_packet, sizeof(ack_tcp_packet));
	*tx_desc.len = sizeof(ack_tcp_packet);

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
send_tcp_data(tcp_conn_t *conn, uint8_t *packet_buf, uint8_t *data, uint16_t len) {

	log_debug1("send tcp data packet");

	data_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	data_tcp_packet.opts.ts.echo = conn->ts;

	data_tcp_packet.tcp.dst_port = conn->key->src_port;
	data_tcp_packet.tcp.ack      = htonl(conn->last_recv_byte + 1);
	data_tcp_packet.tcp.seq      = htonl(conn->last_sent_byte);
	data_tcp_packet.tcp.checksum = 0;

	memcpy(&data_tcp_packet.ip.dst_addr, &conn->key->src_addr, sizeof(struct in_addr));
	data_tcp_packet.ip.total_len  = HTONS(sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + sizeof(tcp_data_opts_t) + len);
	data_tcp_packet.ip.check      = 0;
	data_tcp_packet.ip.check      = checksum((uint8_t *) &data_tcp_packet.ip, sizeof(ip_hdr_t));

	data_tcp_packet.tcp.checksum = tcp_data_checksum(&data_tcp_packet.ip, &data_tcp_packet.tcp, &data_tcp_packet.opts, data, len);

	memcpy(data_tcp_packet.eth.mac_dst, conn->src_mac, sizeof(struct ether_addr));

	memcpy(packet_buf, &data_tcp_packet, sizeof(data_tcp_packet));
}

void
send_tcp_fin_ack(packet_t *p, tcp_conn_t *conn) {

	netmap_tx_ring_desc_t tx_desc;
	log_debug1("send tcp FIN+ACK packet");

	fin_ack_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	fin_ack_tcp_packet.opts.ts.echo = conn->ts;

	fin_ack_tcp_packet.tcp.dst_port = p->tcp_hdr->src_port;
	fin_ack_tcp_packet.tcp.ack      = htonl(conn->last_recv_byte + 1);
	fin_ack_tcp_packet.tcp.seq      = htonl(conn->last_sent_byte);
	fin_ack_tcp_packet.tcp.checksum = 0;

	memcpy(&fin_ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	fin_ack_tcp_packet.ip.check = 0;
	fin_ack_tcp_packet.ip.check = checksum((uint8_t *) &fin_ack_tcp_packet.ip, sizeof(ip_hdr_t));

	fin_ack_tcp_packet.tcp.checksum = tcp_fin_ack_checksum(&fin_ack_tcp_packet.ip, &fin_ack_tcp_packet.tcp, &fin_ack_tcp_packet.opts);

	memcpy(fin_ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	netmap_get_tx_ring_buffer(&tx_desc);
	memcpy(tx_desc.buf, &fin_ack_tcp_packet, sizeof(fin_ack_tcp_packet));
	*tx_desc.len = sizeof(fin_ack_tcp_packet);

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);

}

void
send_tcp_rst(packet_t *p, tcp_conn_t *conn) {

	netmap_tx_ring_desc_t tx_desc;
	log_debug1("send tcp RST packet");

	rst_tcp_packet.tcp.dst_port = p->tcp_hdr->src_port;

	if (conn) {
		rst_tcp_packet.tcp.ack      = htonl(conn->last_recv_byte + 1);
		rst_tcp_packet.tcp.seq      = htonl(conn->last_sent_byte);
	} else {
		rst_tcp_packet.tcp.ack      = p->tcp_hdr->seq + 1;
		rst_tcp_packet.tcp.seq      = 0;
	}
	rst_tcp_packet.tcp.checksum = 0;

	memcpy(&rst_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	rst_tcp_packet.ip.check = 0;
	rst_tcp_packet.ip.check = checksum((uint8_t *) &rst_tcp_packet.ip, sizeof(ip_hdr_t));

	rst_tcp_packet.tcp.checksum = tcp_rst_checksum(&rst_tcp_packet.ip, &rst_tcp_packet.tcp);

	memcpy(rst_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	netmap_get_tx_ring_buffer(&tx_desc);
	memcpy(tx_desc.buf, &rst_tcp_packet, sizeof(rst_tcp_packet));
	*tx_desc.len = sizeof(rst_tcp_packet);

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);

}

void
process_tcp_new_conn(packet_t *p) {
	struct timeval tv;

	if (ntohs(p->tcp_hdr->dst_port) != listening_port) {
		send_tcp_rst(p, NULL);
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
	conn->http_state       = NO_DATA;

	conn->win_scale        = 0;

	log_debug1("recv tcp SYN packet");

	if (p->tcp_hdr->data_offset > 5) {
		parse_tcp_options(p->tcp_hdr, conn);
	}

	send_tcp_syn_ack(p, conn);

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

		send_tcp_ack(p, conn);
		return;
	}

	/*
	 * TODO: check if something got missed and ask for retransmission
	 */

	if (len) {
		/* TODO: if the PSH flag is not set, enqueue the incomplete
		 * payload and wait for the other segments */
		payload = ((char *) p->tcp_hdr) + (p->tcp_hdr->data_offset * 4);

		conn->last_recv_byte += len;
		send_tcp_ack(p, conn);

		/* XXX: here we are using the NIC payload string, maybe we
		 * should copy the request to avoid the possibility that the
		 * packet will be overwritten during the processing */
		conn->http_response = handle_http_request(payload, len);
		conn->http_state    = HTTP_HEADER;

	}

	if (p->tcp_hdr->flags & TCP_FLAG_ACK) {

		conn->last_ackd_byte   = ntohl(p->tcp_hdr->ack);
		conn->effective_window = (p->tcp_hdr->window << conn->win_scale) -
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

	send_tcp_fin_ack(p, conn);
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
		}
	} else {
		if (p->tcp_hdr->flags == TCP_FLAG_SYN) {
			process_tcp_new_conn(p);
		} else {
			send_tcp_rst(p, NULL);
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

	sum = partial_checksum(sum, (const uint8_t *) &pseudo_hdr, sizeof(tcp_pseudo_header_t));
	sum = partial_checksum(sum, (const uint8_t *) tcp_hdr, sizeof(tcp_hdr_t));
	sum = partial_checksum(sum, opts, opts_len);
	sum = finalize_checksum(sum, data, data_len);

	return sum;
}

int
tcp_conn_has_data_to_send(tcp_conn_t *conn) {
	return conn->http_state != NO_DATA && conn->effective_window;
}

void
tcp_conn_send_data(tcp_conn_t *conn, netmap_tx_ring_desc_t *tx_buf) {
	char  *payload_buf;
	uint16_t payload_len;
	uint16_t file_read;

	http_response_t *http_res;

	/* tcp_conn_send_data is called only after tcp_conn_has_data_to_send, so
	 * we know for sure that conn->http_state is either HTTP_HEADER or
	 * FILE_TRASNFERING */

	payload_buf = TCP_DATA_PACKET_PAYLOAD(tx_buf->buf);
	http_res    = conn->http_response;

	if (conn->http_state == HTTP_HEADER) {
		/*
		 * XXX for now we can assume http header will fit in a single packet segment
		 */

		memcpy(payload_buf, http_res->header_buf, http_res->header_len);
	}

	if (http_res->file_len) {
		file_read = read(http_res->file_fd, payload_buf + http_res->header_len,
				MIN(ETH_MTU - sizeof(data_tcp_packet) - http_res->header_len, http_res->file_len - http_res->file_pos)); /* assuming we are on ethernet */
	} else {
		file_read = 0;
	}

	payload_len = file_read + http_res->header_len;

	send_tcp_data(conn, (uint8_t *) tx_buf->buf, (uint8_t *) payload_buf, payload_len);
	*tx_buf->len = sizeof(data_tcp_packet) + payload_len;

	http_res->file_pos     += file_read;
	conn->last_sent_byte   += payload_len;
	conn->effective_window -= payload_len;

	if (conn->http_state == HTTP_HEADER) {
		http_res->header_len = 0;
		conn->http_state     = FILE_TRANSFERING;
	}

	if (http_res->file_pos == http_res->file_len) {
		conn->http_state = NO_DATA;

		free(http_res->header_buf);
		free(http_res->parser);

		close(http_res->file_fd);

	}
}

