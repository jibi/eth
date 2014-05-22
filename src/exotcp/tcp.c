#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth/log.h>

#include <eth/exotcp.h>
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

#include <glib.h>

GHashTable *tcb_hash;

struct {
	eth_hdr_t eth;
	ip_hdr_t  ip;
	tcp_hdr_t tcp;
} prebuild_tcp_packet;

void
init_prebuild_tcp_packet() {
	memcpy(prebuild_tcp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	prebuild_tcp_packet.eth.mac_type       = ETH_TYPE_ARP;

	prebuild_tcp_packet.ip.version     = 4;
	prebuild_tcp_packet.ip.hdr_len     = 5;
	prebuild_tcp_packet.ip.tos         = 0;
	//prebuild_tcp_packet.ip.total_len = tbd;
	prebuild_tcp_packet.ip.id          = 0;
	prebuild_tcp_packet.ip.flags       = 0x2; /* dont fragment */
	prebuild_tcp_packet.ip.frag_offset = 0;
	prebuild_tcp_packet.ip.ttl         = 64;
	prebuild_tcp_packet.ip.proto       = IP_PROTO_TCP;
	//prebuild_tcp_packet.ip.check     = tbd;
	memcpy(&prebuild_tcp_packet.ip.src_addr, &ip_addr, sizeof(struct in_addr));
	//prebuild_tcp_packet.ip.dst_addr  = tbd;
	
	prebuild_tcp_packet.tcp.src_port    = HTONS(8080);
	//prebuild_tcp_packet.tcp.dst_port  = HTONS(8080);
	prebuild_tcp_packet.tcp.data_offset = 4;
	prebuild_tcp_packet.tcp.res         = 0;
	prebuild_tcp_packet.tcp.window      = HTONS(0x4000); /* XXX */
}

static uint32_t
murmur_hash( const void * key, int len, uint32_t seed ) {
	const uint32_t m          = 0x5bd1e995;
	const int r               = 24;
	uint32_t h                = seed ^ len;
	const unsigned char *data = (const unsigned char *)key;

	while (len >= 4) {
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch(len) {
		case 3: h ^= data[2] << 16;
		case 2: h ^= data[1] << 8;
		case 1: h ^= data[0];
			h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

static guint
hash_tcp_conn(gconstpointer t) {
	return murmur_hash(t, sizeof(tcp_conn_key_t), 0);
}

static gboolean
cmp_tcp_conn(gconstpointer t1, gconstpointer t2) {
	return !memcmp(t1, t2, sizeof(tcp_conn_key_t));
}


void
init_tcp() {
	init_prebuild_tcp_packet();

	tcb_hash = g_hash_table_new(hash_tcp_conn, cmp_tcp_conn);
}

void
parse_tcp_options(tcp_hdr_t *tcp_hdr, tcp_conn_t *conn) {
	char *cur_opt;
	cur_opt = ((char *) tcp_hdr) + 5 * 4;

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
				conn->win_scaling = 1;

				cur_opt += 3;
				break;
			case 4:
				log_debug2("sack permitted");
				conn->sack_permitted = 1;

				cur_opt += 2;
				break;
			case 5:
				log_debug2("sack");

				cur_opt += *(cur_opt + 1);
				break;
			case 8:
				log_debug2("timestamp");
				conn->timestamp      = (int) *(cur_opt + 2);
				conn->echo_timestamp = (int) *(cur_opt + 6);

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
process_tcp_new_conn(char *packet_buf) {
	ip_hdr_t *ip_hdr   = (ip_hdr_t *)  (packet_buf + sizeof(eth_hdr_t));
	tcp_hdr_t *tcp_hdr = (tcp_hdr_t *) (packet_buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));

	tcp_conn_key_t *conn_key = malloc(sizeof(tcp_conn_key_t));
	tcp_conn_t     *conn     = malloc(sizeof(tcp_conn_t));

	conn->key = conn_key;
	conn->key->src_port = tcp_hdr->src_port;
	conn->key->src_addr = ip_hdr->src_addr;
	conn->ack           = tcp_hdr->ack;
	conn->seq           = tcp_hdr->seq;
	conn->state         = SYN_RCVD;

	log_debug1("recv TCP syn");

	if (tcp_hdr->data_offset > 5) {
		parse_tcp_options(tcp_hdr, conn);
	}
}

void
process_tcp_new_conn_ack(char *packet_buf) {
	ip_hdr_t *ip_hdr   = (ip_hdr_t *)  (packet_buf + sizeof(eth_hdr_t));
	tcp_hdr_t *tcp_hdr = (tcp_hdr_t *) (ip_hdr + sizeof(ip_hdr_t));
	tcp_conn_t *conn;

	tcp_conn_key_t key = {
		.src_port = tcp_hdr->src_port,
		.src_addr = ip_hdr->src_addr
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
process_tcp_segment(char *packet_buf) {

}

void
process_tcp(char *packet_buf) {
	tcp_hdr_t *tcp_hdr = (tcp_hdr_t *) (packet_buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));

	if (tcp_hdr->flags == TCP_FLAG_SYN) {
		process_tcp_new_conn(packet_buf);
	} else if (tcp_hdr->flags == (TCP_FLAG_SYN | TCP_FLAG_ACK)) {
		process_tcp_new_conn_ack(packet_buf);
	} else {
		process_tcp_segment(packet_buf);
	}
}

/*
void
hash_test() {

	tcp_conn_key_t t1, t2;
	t1.src_port = 1;
	t1.src_addr = 2;

	t2.src_port = 2;
	t2.src_addr = 2;

	g_hash_table_insert(hash, &t1, "Richmond");
	g_hash_table_insert(hash, &t1, "Austin");
	g_hash_table_insert(hash, &t2, "Columbus");

	printf("There are %d keys in the hash\n", g_hash_table_size(hash));
	printf("The capital of Texas is %s\n", g_hash_table_lookup(hash, &t1));
	gboolean found = g_hash_table_remove(hash, "Virginia");

	printf("The value 'Virginia' was %sfound and removed\n", found ? "" : "not ");

	g_hash_table_destroy(hash);

}
*/

