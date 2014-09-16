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
#include <eth/exotcp/tcp.h>
#include <eth/netmap.h>

#include <glib.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

struct nm_desc *netmap;

void
init_netmap(char *ifname) {
	char _ifname[IFNAMSIZ + 7];

	sprintf(_ifname, "netmap:%s", ifname);
	netmap = nm_open(_ifname, NULL, NETMAP_NO_TX_POLL, 0);

	if (!netmap) {
		fatal_tragedy(1, "Cannot open netmap device");
	}
}

void
nm_loop(void (*process_packet)(char *, size_t len)) {
	while (1) {
		struct pollfd recv_fds, send_fds;
		struct netmap_ring *recv_ring, *send_ring;
		unsigned int i, idx, len;
		char *buf;
		bool has_data_to_send = true;
		bool resume_loop = false;

		GHashTableIter iter;
		gpointer key, value;

		recv_fds.fd     = NETMAP_FD(netmap);
		recv_fds.events = POLLIN;

		poll(&recv_fds, 1, has_data_to_send ? -1 : 0);

		recv_ring = NETMAP_RXRING(netmap->nifp, 0);

		while (!nm_ring_empty(recv_ring)) {
			i   = recv_ring->cur;
			idx = recv_ring->slot[i].buf_idx;

			buf = NETMAP_BUF(recv_ring, idx);
			len = recv_ring->slot[i].len;

			process_packet(buf, len);

			recv_ring->head = recv_ring->cur = nm_ring_next(recv_ring, i);
		}

		send_fds.fd     = NETMAP_FD(netmap);
		send_fds.events = POLLOUT;

		poll(&send_fds, 1, -1);
		send_ring = NETMAP_TXRING(netmap->nifp, 0);

		while (!nm_ring_empty(send_ring) && has_data_to_send) {
			if (! resume_loop) {
				g_hash_table_iter_init (&iter, tcb_hash);
			}

			resume_loop      = false;
			has_data_to_send = false;

			while (g_hash_table_iter_next (&iter, &key, &value)) {
				tcp_conn_t *conn = value;

				if (nm_ring_empty(send_ring)) {
					resume_loop = true;
					break;
				}

				if (tcp_conn_has_data_to_send(conn)) {
					tcp_conn_send_data(conn);
					has_data_to_send = true;
				}
			}
		}

		ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
	}
}

int
nm_get_tx_buff_no_poll(nm_tx_desc_t *tx_desc) {
	struct netmap_ring *ring;
	int i, idx;

	ring = NETMAP_TXRING(netmap->nifp, 0);

	if (nm_ring_empty(ring)) {
		return 0;
	}

	i    = ring->cur;
	idx  = ring->slot[i].buf_idx;

	tx_desc->buf  = NETMAP_BUF(ring, idx);
	tx_desc->len = &ring->slot[i].len;

	ring->head = ring->cur = nm_ring_next(ring, i);

	return 1;
}

int
nm_get_tx_buff(nm_tx_desc_t *tx_desc) {
	struct pollfd fds;

	fds.fd     = NETMAP_FD(netmap);
	fds.events = POLLOUT;

	poll(&fds, 1, -1);

	return nm_get_tx_buff_no_poll(tx_desc);
}

