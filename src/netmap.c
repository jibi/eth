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
#include <eth/datastruct/judy.h>

struct nm_desc *netmap;
list_head_t    *nm_tcp_conn_list;
tcp_conn_t     *nm_send_loop_cur_conn = NULL;

static bool nm_did_send_last_time   = false;
static bool nm_recv_loop_has_sent;

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
nm_sync_pending_tx() {
	while (nm_tx_pending(NETMAP_TXRING(netmap->nifp, 0))) {
		ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
	}
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
nm_sync_rx_tx_ring(void)
{
	int timeout;
	struct pollfd nm_fds;

	nm_fds.fd     = NETMAP_FD(netmap);
	nm_fds.events = POLLIN;

	/* the timeout logic is the following:
	 *
	 * * if nm_did_send_data_last_time is true, it means probably there's more
	 *   data to send available, so just set a timeout equal to 0
	 *
	 * * Otherwise, in case there are packets that are not yet acknowledged, set the timeout
	 *   to the the earlier timeout of retransmission.
	 *
	 * * Otherwise put poll in a blocking state
	 */

	if (nm_did_send_last_time) {
		timeout = 0;
	} else if (!judy_empty(conns_min_retx_ts)) {
		tcp_min_retx_ts_list_t *min_retx_ts = *judy_get_first(conns_min_retx_ts);
		timeout = min_retx_ts->retx_ts - cur_ms_ts();
	} else {
		timeout = -1;
	}

	poll(&nm_fds, 1, timeout);

	nm_sync_pending_tx();
}

static inline
void
nm_recv_loop(void)
{
	struct netmap_ring *recv_ring;

	recv_ring             = NETMAP_RXRING(netmap->nifp, 0);
	nm_recv_loop_has_sent = false;

	while (!nm_ring_empty(recv_ring)) {
		recv_packet(recv_ring);
	}

	if (nm_recv_loop_has_sent) {
		ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
	}
}

static inline
void
nm_retx_loop(void)
{
	uint64_t min_seg_index;
	void   **min_seg_value;

	bool did_retx = false;

	/*
	 * global Judy array with min_retx_ts lists
	 */
	judy_for_each(conns_min_retx_ts, min_seg_index, min_seg_value) {
		tcp_min_retx_ts_list_t *min_retx_ts_list;
		tcp_min_retx_ts_t *min_retx_ts, *tmp;

		min_retx_ts_list = *min_seg_value;

		if (min_retx_ts_list->retx_ts >= cur_ms_ts()) {
			break;
		}

		/*
		 * min_retx_ts list, each entry is a connection
		 */
		list_for_each_entry_safe(min_retx_ts, tmp, &min_retx_ts_list->ts_list_head, head) {
			uint64_t segs_list_index;
			void   **segs_list_value;

			set_cur_conn(min_retx_ts->conn);
			set_cur_sock(cur_conn->sock)

			/*
			 * connection's Jidy array with segments lists
			 */
			judy_for_each(cur_conn->unackd_segs_by_ts, segs_list_index, segs_list_value) {
				tcp_unackd_segs_list_t *segs_list;
				tcp_unackd_seg_t       *seg, *tmp;

				segs_list = *segs_list_value;

				list_for_each_entry_safe(seg, tmp, &segs_list->ts_list_head, ts_list_head) {
					if (seg->retx_ts >= cur_ms_ts()) {
						break;
					}

					if (seg->ackd) {
						list_del(&seg->ts_list_head);
						free_unackd_seg(seg);
					} else {
						did_retx = true;
						tcp_retransm_segment(seg);
					}
				}

				if (list_empty(&segs_list->ts_list_head)) {
					judy_del(&cur_conn->unackd_segs_by_ts, segs_list_index);
					free_unackd_segs_list(segs_list);
				}
			}

			if (judy_empty(cur_conn->unackd_segs_by_ts)) {
				/*
				 * remove entry from global retx list
				 */
				list_del(&min_retx_ts_list->ts_list_head);
			}
		}

		if (list_empty(&min_retx_ts_list->ts_list_head)) {
			judy_del(&conns_min_retx_ts, min_seg_index);
			free_min_retx_ts_list(min_retx_ts_list);
		}
	}

	if (did_retx) {
		ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
	}
}

static inline
void
nm_send_loop(void)
{
	struct netmap_ring *send_ring;
	static bool resume_loop = false;

	send_ring = NETMAP_TXRING(netmap->nifp, 0);

	do {
		if (unlikely(!resume_loop)) {
			nm_send_loop_cur_conn = list_first_entry(nm_tcp_conn_list, tcp_conn_t, nm_tcp_conn_list_head);
		}

		resume_loop           = false;
		nm_did_send_last_time = false;

		tcp_conn_t *n;
		list_for_each_entry_safe_from(nm_send_loop_cur_conn, n, nm_tcp_conn_list, nm_tcp_conn_list_head) {
			set_cur_conn(nm_send_loop_cur_conn);

			if (unlikely(nm_ring_empty(send_ring))) {
				resume_loop = true;
				break;
			}

			if (tcp_conn_has_data_to_send()) {
				set_cur_sock(cur_conn->sock);

				tcp_conn_send_data();
				nm_did_send_last_time = true;
			}
		}
	} while ((!nm_ring_empty(send_ring)) && nm_did_send_last_time);
}

void
nm_loop(void)
{
	while (1) {
		nm_sync_rx_tx_ring();

		nm_recv_loop();

		nm_retx_loop();
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

	if (nm_ring_empty(ring)) {
		log_warn("send ring full in nm_get_tx_buff(), syncing");
		ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
	}

	i    = ring->cur;
	idx  = ring->slot[i].buf_idx;

	tx_desc->buf  = NETMAP_BUF(ring, idx);
	tx_desc->len = &ring->slot[i].len;

	ring->head = ring->cur = nm_ring_next(ring, i);
}

void
nm_send_packet(void *packet, uint16_t packet_len)
{
	nm_tx_desc_t tx_desc;

	nm_get_tx_buff(&tx_desc);
	memcpy(tx_desc.buf, packet, packet_len);
	*tx_desc.len = packet_len;

	nm_recv_loop_has_sent = true;
}

void
nm_send_packet_with_data(void *packet, uint16_t packet_len, void *data, uint16_t data_len)
{
	nm_tx_desc_t tx_desc;

	nm_get_tx_buff(&tx_desc);
	memcpy(tx_desc.buf, packet, packet_len);
	memcpy(tx_desc.buf + packet_len, data, data_len);
	*tx_desc.len = packet_len + data_len;

	nm_recv_loop_has_sent = true;
}

