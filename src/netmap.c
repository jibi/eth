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
#include <fcntl.h>
#include <poll.h>

#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <eth.h>
#include <eth/log.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/tcp.h>
#include <eth/netmap.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <eth/datastruct/list.h>

struct nm_desc *netmap;
list_head_t    *nm_tcp_conn_list;

static bool nm_has_data_to_send = false;

void
init_netmap(char *ifname)
{
	char _ifname[IFNAMSIZ + 7];

	sprintf(_ifname, "netmap:%s", ifname);
	netmap = nm_open(_ifname, NULL, 0, 0);

	if (!netmap) {
		fatal_tragedy(1, "Cannot open netmap device");
	}

	nm_tcp_conn_list = list_new();
}

static inline
void
process_packet(char *buf, size_t len)
{
	packet_t p;
	socket_t s;

	p.buf = buf;
	p.len = len;

	set_cur_pkt(&p);
	set_cur_sock(&s);

	process_eth();
}

static inline
void
recv_packet(struct netmap_ring *recv_ring)
{
	unsigned int i, idx, len;
	char *buf;

	i   = recv_ring->cur;
	idx = recv_ring->slot[i].buf_idx;

	buf = NETMAP_BUF(recv_ring, idx);
	len = recv_ring->slot[i].len;

	process_packet(buf, len);

	recv_ring->head = recv_ring->cur = nm_ring_next(recv_ring, i);

}

static inline
void
nm_sync_rx_tx_ring() {
	struct pollfd nm_fds;
	nm_fds.fd     = NETMAP_FD(netmap);
	nm_fds.events = POLLIN;

	poll(&nm_fds, 1, nm_has_data_to_send ? 0 : -1);
}

static inline
void
nm_recv_loop(void)
{
	struct netmap_ring *recv_ring;

	recv_ring = NETMAP_RXRING(netmap->nifp, 0);

	while (!nm_ring_empty(recv_ring)) {
		recv_packet(recv_ring);
	}

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

static inline
void
nm_send_loop(void)
{
	struct netmap_ring *send_ring;
	static bool resume_loop = false;
	static tcp_conn_t *conn = NULL;

	send_ring = NETMAP_TXRING(netmap->nifp, 0);

	nm_has_data_to_send = true;
	while (!nm_ring_empty(send_ring) && nm_has_data_to_send) {

		if (unlikely(!resume_loop)) {
			conn = list_first_entry(nm_tcp_conn_list, tcp_conn_t, nm_tcp_conn_list_head);
		}

		resume_loop         = false;
		nm_has_data_to_send = false;

		tcp_conn_t *n;
		list_for_each_entry_safe_from(conn, n, nm_tcp_conn_list, nm_tcp_conn_list_head) {
			if (unlikely(nm_ring_empty(send_ring))) {
				resume_loop = true;
				break;
			}

			set_cur_conn(conn);

			if (tcp_conn_has_data_to_send()) {
				set_cur_sock(conn->sock);

				tcp_conn_send_data();
				nm_has_data_to_send = true;
			}
		}
	}

}

void
nm_loop(void)
{
	while (1) {
		nm_sync_rx_tx_ring();

		nm_recv_loop();
		nm_send_loop();
	}
}

int
nm_send_ring_empty(void)
{
	struct netmap_ring *ring;
	ring = NETMAP_TXRING(netmap->nifp, 0);

	return nm_ring_empty(ring);
}

void
nm_get_tx_buff(nm_tx_desc_t *tx_desc)
{
	struct netmap_ring *ring;
	int i, idx;

	ring = NETMAP_TXRING(netmap->nifp, 0);

	i    = ring->cur;
	idx  = ring->slot[i].buf_idx;

	tx_desc->buf  = NETMAP_BUF(ring, idx);
	tx_desc->len = &ring->slot[i].len;

	ring->head = ring->cur = nm_ring_next(ring, i);

}

/*
 * since:
 * - nm_send_packet and nm_send_packet_with_data are called only:
 *   - during the nm_recv_loop
 *   - once for each packet received
 * - we can assume that the NIC send ring is the same size of the recv ring
 *
 * we are assured that nm_get_tx_buff will always return a tx_buff.
 */
void
nm_send_packet(void *packet, uint16_t packet_len)
{
	nm_tx_desc_t tx_desc;

	nm_get_tx_buff(&tx_desc);
	memcpy(tx_desc.buf, packet, packet_len);
	*tx_desc.len = packet_len;
}

void
nm_send_packet_with_data(void *packet, uint16_t packet_len, void *data, uint16_t data_len)
{
	nm_tx_desc_t tx_desc;

	nm_get_tx_buff(&tx_desc);
	memcpy(tx_desc.buf, packet, packet_len);
	memcpy(tx_desc.buf + packet_len, data, data_len);
	*tx_desc.len = packet_len + data_len;
}

