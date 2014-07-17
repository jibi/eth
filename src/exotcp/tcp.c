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

static uint16_t tcp_syn_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_syn_ack_opts_t *tcp_opts);
static uint16_t tcp_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_ack_opts_t *tcp_opts);

int
get_tcp_clock(tcp_conn_t *conn) {
	struct timeval tv;
	uint32_t       clock;

	gettimeofday(&tv, 0);

	clock = tv.tv_sec / 1000 + tv.tv_usec * 1000;

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

	syn_ack_tcp_packet.tcp.src_port    = HTONS(8080);
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
	ack_tcp_packet.tcp.src_port    = HTONS(8080);
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
init_tcp() {
	log_debug2("init_tcp");

	init_syn_ack_tcp_packet();
	init_ack_tcp_packet();

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
				conn->win_scale = 1;

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

	log_debug2("send tcp SYN+ACK packet");

	/* XXX */
	syn_ack_tcp_packet.opts.mss.size        = HTONS(TCP_MSS);
	syn_ack_tcp_packet.opts.ts.ts           = htonl(get_tcp_clock(conn));
	syn_ack_tcp_packet.opts.ts.echo         = conn->ts;
	syn_ack_tcp_packet.opts.win_scale.shift = TCP_WIN_SCALE;

	syn_ack_tcp_packet.tcp.dst_port = p->tcp_hdr->src_port;
	syn_ack_tcp_packet.tcp.ack      = htonl(conn->last_ack);
	syn_ack_tcp_packet.tcp.seq      = htonl(conn->cur_seq);
	syn_ack_tcp_packet.tcp.checksum = 0;

	memcpy(&syn_ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	syn_ack_tcp_packet.ip.check = 0;
	syn_ack_tcp_packet.ip.check = checksum((const char *) &syn_ack_tcp_packet.ip, sizeof(ip_hdr_t));

	syn_ack_tcp_packet.tcp.checksum = tcp_syn_ack_checksum(&syn_ack_tcp_packet.ip, &syn_ack_tcp_packet.tcp, &syn_ack_tcp_packet.opts);

	memcpy(syn_ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	nm_inject(netmap, &syn_ack_tcp_packet, sizeof(syn_ack_tcp_packet));
	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
send_tcp_ack(packet_t *p, tcp_conn_t *conn) {

	log_debug2("send tcp ACK packet");

	ack_tcp_packet.opts.ts.ts   = htonl(get_tcp_clock(conn));
	ack_tcp_packet.opts.ts.echo = conn->ts;

	ack_tcp_packet.tcp.dst_port = p->tcp_hdr->src_port;
	ack_tcp_packet.tcp.ack      = htonl(conn->last_ack);
	ack_tcp_packet.tcp.seq      = htonl(conn->cur_seq);
	ack_tcp_packet.tcp.checksum = 0;

	memcpy(&ack_tcp_packet.ip.dst_addr, &p->ip_hdr->src_addr, sizeof(struct in_addr));
	ack_tcp_packet.ip.check = 0;
	ack_tcp_packet.ip.check = checksum((const char *) &ack_tcp_packet.ip, sizeof(ip_hdr_t));

	ack_tcp_packet.tcp.checksum = tcp_ack_checksum(&ack_tcp_packet.ip, &ack_tcp_packet.tcp, &ack_tcp_packet.opts);

	memcpy(ack_tcp_packet.eth.mac_dst, p->eth_hdr->mac_src, sizeof(struct ether_addr));

	nm_inject(netmap, &ack_tcp_packet, sizeof(ack_tcp_packet));
	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
process_tcp_new_conn(packet_t *p) {
	struct timeval tv;

	tcp_conn_key_t *conn_key = malloc(sizeof(tcp_conn_key_t));
	tcp_conn_t     *conn     = malloc(sizeof(tcp_conn_t));

	gettimeofday(&tv, 0);

	conn->key           = conn_key;
	conn->key->src_port = p->tcp_hdr->src_port;
	conn->key->src_addr = p->ip_hdr->src_addr;
	conn->last_ack      = ntohl(p->tcp_hdr->seq);
	conn->cur_seq       = rand();
	conn->state         = SYN_RCVD;
	conn->last_clock    = tv.tv_sec / 1000 + tv.tv_usec * 1000;

	log_debug1("recv tcp SYN packet");

	if (p->tcp_hdr->data_offset > 5) {
		parse_tcp_options(p->tcp_hdr, conn);
	}

	/*
	 * with a SYN packet we need to ACK one byte.
	 */
	conn->last_ack++;

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

	conn->cur_seq++;

	log_debug1("new connection established");
	conn->state = ESTABLISHED;
}

void
process_tcp_segment(packet_t *p, tcp_conn_t *conn) {
	char *payload;
	uint16_t  len = (ntohs(p->ip_hdr->total_len) - sizeof(ip_hdr_t) - (p->tcp_hdr->data_offset * 4));

	parse_tcp_options(p->tcp_hdr, conn);

	if (len) {
		payload = ((char *) p->tcp_hdr) + (p->tcp_hdr->data_offset * 4);
		log_info("payload:\n%.*s", len, payload);

		conn->last_ack += len;
		send_tcp_ack(p, conn);

	} else {
		log_info("length 0");
	}
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
				process_tcp_segment(p, conn);
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
			/* TODO: send RST */
		}
	}
}

static uint16_t
tcp_syn_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_syn_ack_opts_t *tcp_opts) {
	tcp_pseudo_header_t pseudo_hdr;
	uint32_t sum = 0;

	pseudo_hdr.src_addr = ip_hdr->src_addr;
	pseudo_hdr.dst_addr = ip_hdr->dst_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.proto    = IP_PROTO_TCP;
	pseudo_hdr.length   = HTONS(sizeof(tcp_hdr_t) + sizeof(tcp_syn_ack_opts_t));

	sum = partial_checksum(sum,  (const char *) &pseudo_hdr, sizeof(tcp_pseudo_header_t));
	sum = partial_checksum(sum,  (const char *) tcp_hdr, sizeof(tcp_hdr_t));
	sum = finalize_checksum(sum, (const char *) tcp_opts, sizeof(tcp_syn_ack_opts_t));

	return sum;
}


static uint16_t
tcp_ack_checksum(ip_hdr_t *ip_hdr, tcp_hdr_t *tcp_hdr, tcp_ack_opts_t *tcp_opts) {
	tcp_pseudo_header_t pseudo_hdr;
	uint32_t sum = 0;

	pseudo_hdr.src_addr = ip_hdr->src_addr;
	pseudo_hdr.dst_addr = ip_hdr->dst_addr;
	pseudo_hdr.reserved = 0;
	pseudo_hdr.proto    = IP_PROTO_TCP;
	pseudo_hdr.length   = HTONS(sizeof(tcp_hdr_t) + sizeof(tcp_ack_opts_t));

	sum = partial_checksum(sum,  (const char *) &pseudo_hdr, sizeof(tcp_pseudo_header_t));
	sum = partial_checksum(sum,  (const char *) tcp_hdr, sizeof(tcp_hdr_t));
	sum = finalize_checksum(sum, (const char *) tcp_opts, sizeof(tcp_ack_opts_t));

	return sum;
}

