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
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>
#include <eth/exotcp/hash.h>

#include <glib.h>

GHashTable *tcb_hash;

struct {
	eth_hdr_t          eth;
	ip_hdr_t           ip;
	tcp_hdr_t          tcp;
	tcp_syn_ack_opts_t opts;
} __attribute__ ((packed)) syn_ack_tcp_packet;

uint16_t tcp_syn_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_syn_ack_opts_t *tcp_opts);

void
init_syn_ack_tcp_packet() {
	/*
	 * tcp header
	 */
	syn_ack_tcp_packet.tcp.src_port    = HTONS(8080);
	syn_ack_tcp_packet.tcp.res         = 0;
	syn_ack_tcp_packet.tcp.window      = HTONS(0x4000); /* XXX */
	syn_ack_tcp_packet.tcp.data_offset = 0xa;
	syn_ack_tcp_packet.tcp.flags       = (TCP_FLAG_SYN | TCP_FLAG_ACK);

	/*
	 * tcp opts
	 */
	syn_ack_tcp_packet.opts.mss.code       = TCP_OPT_MSS_CODE;
	syn_ack_tcp_packet.opts.mss.len        = TCP_OPT_MSS_LEN;

	syn_ack_tcp_packet.opts.sack_perm.code = TCP_OPT_SACK_PERM_CODE;
	syn_ack_tcp_packet.opts.sack_perm.len  = TCP_OPT_SACK_PERM_LEN;

	syn_ack_tcp_packet.opts.ts.code        = TCP_OPT_TS_CODE;
	syn_ack_tcp_packet.opts.ts.len         = TCP_OPT_TS_LEN;

	syn_ack_tcp_packet.opts.nop            = TCP_OPT_NOP_CODE;

	syn_ack_tcp_packet.opts.win_scale.code = TCP_OPT_WIN_SCALE_CODE;
	syn_ack_tcp_packet.opts.win_scale.len  = TCP_OPT_WIN_SCALE_LEN;

	/*
	 * ip header
	 */

	init_ip_packet(&syn_ack_tcp_packet.ip);
	
	/*
	 * eth header
	 */
	memcpy(syn_ack_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	syn_ack_tcp_packet.eth.mac_type = ETH_TYPE_IPV4;
}

void
init_tcp() {
	init_syn_ack_tcp_packet();

	tcb_hash = g_hash_table_new(hash_tcp_conn, cmp_tcp_conn);
}

void
parse_tcp_options(tcp_hdr_t *tcp_hdr, tcp_conn_t *conn) {
	char *cur_opt;
	cur_opt = ((char *) tcp_hdr) + sizeof(tcp_hdr_t);

	log_debug2("tcp options:");

	do {
		log_debug2("cur_opt: %02x", *cur_opt);

		switch (*cur_opt) {
			case 0:
				log_debug2("end of options");
				break;
			case 1:
				log_debug2("no op");

				cur_opt++;
				break;
			case 2:
				log_debug2("mss: %d", (short) *(cur_opt + 2));
				conn->mss = (short) *(cur_opt + 2);

				cur_opt += 4;
				break;
			case 3:
				log_debug2("window scaling");
				conn->win_scale = 1;

				cur_opt += 3;
				break;
			case 4:
				log_debug2("sack permitted");
				conn->sack_perm = 1;

				cur_opt += 2;
				break;
			case 5:
				log_debug2("sack");

				cur_opt += *(cur_opt + 1);
				break;
			case 8:
				log_debug2("ts");
				conn->ts      = *((int *) (cur_opt + 2));
				conn->echo_ts = *((int *) (cur_opt + 6));

				cur_opt += 10;
				break;
			case 14:
				break;
			case 15:
				break;
			default:
				log_debug2("unknown tcp option!");
				cur_opt++;
		}
	} while(*cur_opt != 0 && cur_opt < (((char *) tcp_hdr) + tcp_hdr->data_offset * 4));
}

void
send_tcp_syn_ack(packet_t *p, tcp_conn_t *conn) {
	struct timeval tv;
	gettimeofday(&tv, 0);

	/* XXX: maybe one day figure it out what's happening with this options */
	syn_ack_tcp_packet.opts.mss.size        = 65495;
	syn_ack_tcp_packet.opts.ts.ts           = tv.tv_sec * 1000 + tv.tv_usec;
	syn_ack_tcp_packet.opts.ts.echo         = conn->ts;
	syn_ack_tcp_packet.opts.win_scale.shift = 7;

	syn_ack_tcp_packet.tcp.dst_port    = p->tcp_hdr->src_port;
	syn_ack_tcp_packet.tcp.ack         = htonl(ntohl(conn->remote_seq) + 1);
	syn_ack_tcp_packet.tcp.seq         = conn->local_seq;

	conn->local_seq++;

	syn_ack_tcp_packet.tcp.checksum    = 0;

	memcpy(&syn_ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	syn_ack_tcp_packet.ip.check = 0;
	syn_ack_tcp_packet.ip.check = checksum((const char *) &syn_ack_tcp_packet.ip, sizeof(ip_hdr_t));

	syn_ack_tcp_packet.tcp.checksum = tcp_syn_ack_checksum(&syn_ack_tcp_packet.ip, &syn_ack_tcp_packet.tcp, &syn_ack_tcp_packet.opts);

	memcpy(syn_ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	nm_inject(netmap, &syn_ack_tcp_packet, sizeof(syn_ack_tcp_packet));
	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
process_tcp_new_conn(packet_t *p) {
	tcp_conn_key_t *conn_key = malloc(sizeof(tcp_conn_key_t));
	tcp_conn_t     *conn     = malloc(sizeof(tcp_conn_t));

	conn->key           = conn_key;
	conn->key->src_port = p->tcp_hdr->src_port;
	conn->key->src_addr = p->ip_hdr->src_addr;
	conn->remote_seq    = p->tcp_hdr->seq;
	conn->local_seq     = rand();
	conn->state         = SYN_RCVD;

	log_debug1("recv TCP syn");

	if (p->tcp_hdr->data_offset > 5) {
		parse_tcp_options(p->tcp_hdr, conn);
	}

	send_tcp_syn_ack(p, conn);

	g_hash_table_insert(tcb_hash, conn->key, conn);
}

void
process_tcp_new_conn_ack(packet_t *p) {
	p->tcp_hdr = (tcp_hdr_t *) (p->ip_hdr + sizeof(ip_hdr_t));
	tcp_conn_t *conn;

	tcp_conn_key_t key = {
		.src_port = p->tcp_hdr->src_port,
		.src_addr = p->ip_hdr->src_addr
	};

	conn = g_hash_table_lookup(tcb_hash, &key);
	if (!conn) {
		return;
	}

	if (conn->state != SYN_RCVD) {
		return;
	}

}

void
process_tcp_segment(packet_t *p) {

}

void
process_tcp(packet_t *packet) {
	packet->tcp_hdr = (tcp_hdr_t *) (packet->buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));

	if (packet->tcp_hdr->flags == TCP_FLAG_SYN) {
		process_tcp_new_conn(packet);
	} else if (packet->tcp_hdr->flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
		process_tcp_new_conn_ack(packet);
	} else {
		process_tcp_segment(packet);
	}
}

uint16_t
tcp_syn_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_syn_ack_opts_t *tcp_opts) {
	tcp_pseudo_header_t pseudo_hdr;
	uint32_t sum = 0;

	pseudo_hdr.src_addr = ip_hdr->src_addr;
	pseudo_hdr.dst_addr = ip_hdr->dst_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.proto    = IP_PROTO_TCP;
	pseudo_hdr.length   = HTONS(sizeof(tcp_hdr_t) + sizeof(tcp_syn_ack_opts_t));

	sum = partial_checksum(sum, (const char *) &pseudo_hdr, sizeof(tcp_pseudo_header_t));
	sum = partial_checksum(sum, (const char *) tcp_hdr, sizeof(tcp_hdr_t));
	sum = finalize_checksum(sum, (const char *) tcp_opts, sizeof(tcp_syn_ack_opts_t));

	return sum;
}

