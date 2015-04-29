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

#ifndef _ETH_NETMAP_H
#define _ETH_NETMAP_H

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <eth/datastruct/list.h>
#include <eth/exotcp/tcp.h>

#include <eth/datastruct/async_queue.h>

typedef struct nm_tx_ring_desc_s {
	char *buf;
	uint16_t  *len;
} nm_tx_desc_t;

typedef struct worker_ctx_s {
	async_queue_t *works;
	uint8_t tx_ring_n;
} worker_ctx_t;

extern struct nm_desc *netmap;
extern list_head_t    *nm_tcp_conn_list;
extern tcp_conn_t     *nm_send_loop_cur_conn;

extern pthread_key_t         _cur_tx_ring_n;
#define cur_tx_ring_n        *((uint8_t *) pthread_getspecific(_cur_tx_ring_n))

/*
 * yeah, this is ugly, but meh, since this is called only once from each thread,
 * it's fine (maybe define a destructor for pthread_key_create)
 */
#define set_cur_tx_ring_n(x) {				\
	uint8_t *_tmp = malloc(sizeof(uint8_t));	\
	*_tmp         = x;				\
	pthread_setspecific(_cur_tx_ring_n, _tmp);	\
}

void init_netmap(char *ifname);
void nm_loop(void);
int nm_send_ring_empty(void);
void nm_get_tx_buff(nm_tx_desc_t *tx_desc);
void nm_send_packet(void *packet, uint16_t packet_len);
void nm_send_packet_with_data(void *packet, uint16_t packet_len, void *data, uint16_t data_len);

#endif

